#!/usr/bin/env python3
"""Mock Decky Loader Backend Server.

This server strictly follows the implementation of SteamDeckHomebrew/decky-loader
backend to test client scripts for correctness.

Based on: SteamDeckHomebrew/decky-loader @ 9f586a1b
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

# WebSocket opcodes (RFC 6455)
OP_TEXT = 0x1
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class MessageType:
    """WebSocket message types from backend/decky_loader/wsrouter.py."""
    
    ERROR = -1
    CALL = 0
    REPLY = 1
    EVENT = 3


# Global CSRF token (simulates helpers.get_csrf_token())
CSRF_TOKEN = "decky-" + os.urandom(16).hex()

# Plugin install requests storage (simulates PluginBrowser.install_requests)
install_requests: Dict[str, Dict[str, str]] = {}

# Settings storage (simulates SettingsManager)
settings_store: Dict[str, Any] = {}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("mock_decky_server")


def ws_expected_accept(key: str) -> str:
    """Calculate WebSocket Accept header value.
    
    Args:
        key: The Sec-WebSocket-Key from client handshake.
        
    Returns:
        Base64-encoded SHA-1 hash for Sec-WebSocket-Accept header.
    """
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    sha1 = hashlib.sha1((key + magic).encode("ascii")).digest()
    return base64.b64encode(sha1).decode("ascii")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket.
    
    Args:
        sock: The socket to receive from.
        n: Number of bytes to receive.
        
    Returns:
        Exactly n bytes of data.
        
    Raises:
        ConnectionError: If socket closes before receiving n bytes.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def ws_recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Receive a WebSocket frame.
    
    Args:
        sock: The WebSocket socket.
        
    Returns:
        Tuple of (opcode, payload).
    """
    b1, b2 = recv_exact(sock, 2)
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F

    if length == 126:
        (length,) = struct.unpack("!H", recv_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", recv_exact(sock, 8))

    mask_key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return opcode, payload


def ws_send_frame(sock: socket.socket, opcode: int, payload: bytes) -> None:
    """Send a WebSocket frame.
    
    Server-to-client frames are not masked per RFC 6455.
    
    Args:
        sock: The WebSocket socket.
        opcode: WebSocket opcode (e.g., OP_TEXT, OP_CLOSE).
        payload: Frame payload bytes.
    """
    fin = 0x80
    first = fin | (opcode & 0x0F)
    length = len(payload)

    if length < 126:
        header = struct.pack("!BB", first, length)
    elif length < (1 << 16):
        header = struct.pack("!BBH", first, 126, length)
    else:
        header = struct.pack("!BBQ", first, 127, length)

    sock.sendall(header + payload)


def ws_send_json(sock: socket.socket, data: Dict[str, Any]) -> None:
    """Send a JSON message over WebSocket.
    
    Corresponds to: wsrouter.py async def write()
    
    Args:
        sock: The WebSocket socket.
        data: Dictionary to serialize as JSON.
    """
    text = json.dumps(data, ensure_ascii=False)
    ws_send_frame(sock, OP_TEXT, text.encode("utf-8"))
    logger.info("← WS SEND: %s", text)


def ws_emit(sock: socket.socket, event: str, *args: Any) -> None:
    """Send an EVENT message to the frontend.
    
    Corresponds to: wsrouter.py async def emit()
    
    Args:
        sock: The WebSocket socket.
        event: Event name string.
        *args: Event arguments.
    """
    msg = {
        "type": MessageType.EVENT,
        "event": event,
        "args": list(args)
    }
    ws_send_json(sock, msg)


def handle_call_route(
    sock: socket.socket,
    route: str,
    args: List[Any],
    call_id: int,
    config: Dict[str, bool]
) -> None:
    """Handle a CALL message by routing to appropriate handler.
    
    Corresponds to: wsrouter.py async def _call_route()
    
    Args:
        sock: The WebSocket socket.
        route: Route name (e.g., "utilities/install_plugin").
        args: List of arguments for the route handler.
        call_id: Call ID for matching request/response.
        config: Server configuration dictionary.
    """
    logger.info("Started PY call %s ID %s", route, call_id)
    
    # Route table (corresponds to various ws.add_route() calls)
    routes = {
        "utilities/ping": handle_ping,
        "utilities/install_plugin": handle_install_plugin,
        "utilities/confirm_plugin_install": handle_confirm_plugin_install,
        "utilities/cancel_plugin_install": handle_cancel_plugin_install,
        "utilities/settings/get": handle_get_setting,
        "utilities/settings/set": handle_set_setting,
    }
    
    if route not in routes:
        # Route not found (wsrouter.py line 117)
        error = {
            "error": f'Route {route} does not exist.',
            "name": "RouteNotFoundError",
            "traceback": None
        }
        ws_send_json(sock, {
            "type": MessageType.ERROR,
            "id": call_id,
            "error": error
        })
        return
    
    # Call the route handler
    try:
        result = routes[route](sock, args, config)
        
        # Send REPLY (wsrouter.py line 79)
        ws_send_json(sock, {
            "type": MessageType.REPLY,
            "id": call_id,
            "result": result
        })
    except Exception as err:
        # Send ERROR (wsrouter.py line 77)
        import traceback
        error = {
            "name": err.__class__.__name__,
            "message": str(err),
            "traceback": traceback.format_exc()
        }
        ws_send_json(sock, {
            "type": MessageType.ERROR,
            "id": call_id,
            "error": error
        })


def handle_ping(sock: socket.socket, args: List[Any], config: Dict[str, bool]) -> str:
    """Handle utilities/ping route.
    
    Corresponds to: utilities.py async def ping()
    
    Args:
        sock: The WebSocket socket.
        args: Route arguments (unused).
        config: Server configuration (unused).
        
    Returns:
        String "pong".
    """
    return "pong"


def handle_install_plugin(
    sock: socket.socket,
    args: List[Any],
    config: Dict[str, bool]
) -> Any:
    """Handle utilities/install_plugin route.
    
    Corresponds to:
        - utilities.py async def install_plugin() (line 122-129)
        - browser.py async def request_plugin_install() (line 307-311)
    
    Function signature from utilities.py:
        async def install_plugin(self, artifact: str="", name: str="No name", 
                                version: str="dev", hash: str="", 
                                install_type: PluginInstallType=PluginInstallType.INSTALL)
    
    Args:
        sock: The WebSocket socket.
        args: [artifact, name, version, hash, install_type].
        config: Server configuration dictionary.
        
    Returns:
        None for normal mode (waits for confirm), or dict for auto-confirm mode.
    """
    # Parse arguments according to real function signature
    artifact = args[0] if len(args) > 0 else ""
    name = args[1] if len(args) > 1 else "No name"
    version = args[2] if len(args) > 2 else "dev"
    hash_val = args[3] if len(args) > 3 else ""
    install_type = args[4] if len(args) > 4 else 0
    
    logger.info(
        "[install_plugin] artifact=%s, name=%s, version=%s, hash=%s, install_type=%s",
        artifact,
        name,
        version,
        hash_val,
        install_type,
    )
    
    if config.get("simulate_error"):
        raise RuntimeError("Simulated installation error")
    
    # Generate request_id using time() (browser.py line 308)
    request_id = str(time.time())
    
    # Store install request
    install_requests[request_id] = {
        "artifact": artifact,
        "name": name,
        "version": version,
        "hash": hash_val
    }
    
    if config.get("auto_confirm"):
        # Auto-confirm mode: install directly
        logger.info("[install_plugin] Auto-confirm enabled, installing directly")
        _do_install(sock, artifact, name, version, hash_val)
        return {"status": "installed", "name": name}
    else:
        # Normal mode: send install prompt EVENT
        # emit("loader/add_plugin_install_prompt", name, version, request_id, hash, install_type)
        ws_emit(sock, "loader/add_plugin_install_prompt", 
                name, version, request_id, hash_val, install_type)
        logger.info("[install_plugin] Sent install prompt, request_id=%s", request_id)
        # Real implementation returns None here (async, doesn't wait for confirm)
        return None


def handle_confirm_plugin_install(
    sock: socket.socket,
    args: List[Any],
    config: Dict[str, bool]
) -> Dict[str, Any]:
    """Handle utilities/confirm_plugin_install route.
    
    Corresponds to:
        - utilities.py async def confirm_plugin_install() (line 136-137)
        - browser.py async def confirm_plugin_install() (line 320-325)
    
    From browser.py:
        async def confirm_plugin_install(self, request_id: str):
            requestOrRequests = self.install_requests.pop(request_id)
            if isinstance(requestOrRequests, list):
                [await self._install(...) for req in requestOrRequests]
            else:
                await self._install(requestOrRequests.artifact, ...)
    
    Args:
        sock: The WebSocket socket.
        args: [request_id].
        config: Server configuration (unused).
        
    Returns:
        Dictionary with installation status.
        
    Raises:
        ValueError: If request_id is missing or not found.
    """
    if len(args) < 1:
        raise ValueError("confirm_plugin_install requires request_id argument")
    
    request_id = args[0]
    logger.info("[confirm_plugin_install] request_id=%s", request_id)
    
    # Pop request from storage
    if request_id not in install_requests:
        raise ValueError(f"Install request {request_id} not found")
    
    request_ctx = install_requests.pop(request_id)
    
    # Execute installation
    artifact = request_ctx["artifact"]
    name = request_ctx["name"]
    version = request_ctx["version"]
    hash_val = request_ctx["hash"]
    
    _do_install(sock, artifact, name, version, hash_val)
    
    return {"status": "success", "name": name, "version": version}


def handle_cancel_plugin_install(
    sock: socket.socket,
    args: List[Any],
    config: Dict[str, bool]
) -> None:
    """Handle utilities/cancel_plugin_install route.
    
    Corresponds to:
        - utilities.py async def cancel_plugin_install() (line 139-140)
        - browser.py def cancel_plugin_install() (line 327-328)
    
    Args:
        sock: The WebSocket socket (unused).
        args: [request_id].
        config: Server configuration (unused).
        
    Returns:
        None.
        
    Raises:
        ValueError: If request_id is missing.
    """
    if len(args) < 1:
        raise ValueError("cancel_plugin_install requires request_id argument")
    
    request_id = args[0]
    logger.info("[cancel_plugin_install] request_id=%s", request_id)
    
    install_requests.pop(request_id, None)
    return None


def handle_get_setting(
    sock: socket.socket,
    args: List[Any],
    config: Dict[str, bool]
) -> Any:
    """Handle utilities/settings/get route.
    
    Corresponds to:
        - utilities.py async def get_setting() (line 272)
        - settings.py def getSetting() (line 58)
    
    Function signature from utilities.py:
        async def get_setting(self, key: str, default: Any)
    
    Args:
        sock: The WebSocket socket (unused).
        args: [key, default].
        config: Server configuration (unused).
        
    Returns:
        The setting value or the default if not found.
    """
    if len(args) < 1:
        raise ValueError("get_setting requires key argument")
    
    key = args[0]
    default = args[1] if len(args) > 1 else None
    
    value = settings_store.get(key, default)
    logger.info("[get_setting] key=%s, default=%s, value=%s", key, default, value)
    
    return value


def handle_set_setting(
    sock: socket.socket,
    args: List[Any],
    config: Dict[str, bool]
) -> Any:
    """Handle utilities/settings/set route.
    
    Corresponds to:
        - utilities.py async def set_setting() (line 275)
        - settings.py def setSetting() (line 61)
    
    Function signature from utilities.py:
        async def set_setting(self, key: str, value: Any)
    
    Args:
        sock: The WebSocket socket (unused).
        args: [key, value].
        config: Server configuration (unused).
        
    Returns:
        The value that was set.
        
    Raises:
        ValueError: If key or value is missing.
    """
    if len(args) < 2:
        raise ValueError("set_setting requires key and value arguments")
    
    key = args[0]
    value = args[1]
    
    settings_store[key] = value
    logger.info("[set_setting] key=%s, value=%s", key, value)
    
    return value


def _do_install(sock: socket.socket, artifact: str, name: str, version: str, hash_val: str) -> None:
    """Simulate the installation process with progress events.
    
    Corresponds to: browser.py async def _install() (line 174-307)
    
    Sends a series of EVENT messages to indicate download/install progress.
    Does not actually perform filesystem operations.
    
    Args:
        sock: The WebSocket socket.
        artifact: Plugin artifact URL or path.
        name: Plugin name.
        version: Plugin version.
        hash_val: Plugin hash for verification.
    """
    logger.info("[_install] Installing %s v%s from %s", name, version, artifact)
    
    # Line 174: emit("loader/plugin_download_start", name)
    ws_emit(sock, "loader/plugin_download_start", name)
    
    # Line 175: emit("loader/plugin_download_info", 5, "Store.download_progress_info.start")
    ws_emit(sock, "loader/plugin_download_info", 5, "Store.download_progress_info.start")
    time.sleep(0.1)
    
    # Line 196 or 203: emit("loader/plugin_download_info", 10, "...")
    if artifact.startswith("file://"):
        ws_emit(sock, "loader/plugin_download_info", 10, "Store.download_progress_info.open_zip")
    else:
        ws_emit(sock, "loader/plugin_download_info", 10, "Store.download_progress_info.download_zip")
    time.sleep(0.2)
    
    # Line 213: emit("loader/plugin_download_info", 70, "Store.download_progress_info.increment_count")
    ws_emit(sock, "loader/plugin_download_info", 70, "Store.download_progress_info.increment_count")
    time.sleep(0.1)
    
    # Line 227: emit("loader/plugin_download_info", 75, "Store.download_progress_info.parse_zip")
    ws_emit(sock, "loader/plugin_download_info", 75, "Store.download_progress_info.parse_zip")
    time.sleep(0.2)
    
    # Line 270: emit("loader/plugin_download_info", 80, "Store.download_progress_info.uninstalling_previous")
    # (Only if updating existing plugin - skipped in mock)
    
    # Line 274: emit("loader/plugin_download_info", 90, "Store.download_progress_info.installing_plugin")
    ws_emit(sock, "loader/plugin_download_info", 90, "Store.download_progress_info.installing_plugin")
    time.sleep(0.2)
    
    # Line 282: emit("loader/plugin_download_info", 95, "Store.download_progress_info.download_remote")
    ws_emit(sock, "loader/plugin_download_info", 95, "Store.download_progress_info.download_remote")
    time.sleep(0.3)
    
    # Line 306: emit("loader/plugin_download_finish", name)
    ws_emit(sock, "loader/plugin_download_finish", name)
    
    logger.info("[_install] Completed installation of %s", name)


def handle_websocket_connection(
    client_sock: socket.socket,
    addr: Any,
    config: Dict[str, bool]
) -> None:
    """Handle a WebSocket connection lifecycle.
    
    Corresponds to: wsrouter.py async def handle() (line 81-129)
    
    Args:
        client_sock: The WebSocket socket.
        addr: Client address tuple.
        config: Server configuration dictionary.
    """
    logger.info("WebSocket client connected from %s", addr)
    
    try:
        while True:
            client_sock.settimeout(120)
            opcode, payload = ws_recv_frame(client_sock)
            
            if opcode == OP_PING:
                logger.info("← PING, sending PONG")
                ws_send_frame(client_sock, OP_PONG, payload)
                continue
            
            if opcode == OP_PONG:
                logger.info("← PONG")
                continue
            
            if opcode == OP_CLOSE:
                logger.info("← CLOSE from client")
                ws_send_frame(client_sock, OP_CLOSE, struct.pack("!H", 1000))
                break
            
            if opcode == OP_TEXT:
                text = payload.decode("utf-8", errors="replace")
                logger.info("→ WS RECV: %s", text)
                
                # wsrouter.py line 105-107: handle legacy "close" string
                if text == "close":
                    break
                
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    logger.info("ERROR: Invalid JSON")
                    continue
                
                msg_type = data.get("type")
                
                # wsrouter.py line 110-118: only handle CALL type
                if msg_type == MessageType.CALL:
                    handle_call_route(
                        client_sock,
                        data.get("route"),
                        data.get("args", []),
                        data.get("id"),
                        config
                    )
                else:
                    logger.info("WARNING: Unknown message type %s", msg_type)
    
    except Exception as e:
        logger.info("WebSocket error: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        try:
            client_sock.close()
        except:
            pass
        logger.info("WebSocket client disconnected")


class MockDeckyHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock Decky server.
    
    Handles:
        - GET /auth/token - Returns CSRF token
        - GET /ws?auth=<token> - WebSocket upgrade
    """
    
    config: Dict[str, bool] = {}
    
    def log_message(self, format: str, *args: Any) -> None:
        """Override to use our logging function.
        
        Args:
            format: Format string.
            *args: Format arguments.
        """
        logger.info("HTTP: %s", format % args)
    
    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed = urlparse(self.path)

        # Token endpoint (main.py line 168: async def get_auth_token())
        if parsed.path == "/auth/token":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(CSRF_TOKEN.encode("utf-8"))
            logger.info("Sent CSRF token: %s", CSRF_TOKEN)
            return
        
        # WebSocket upgrade (wsrouter.py line 81-98: async def handle())
        if parsed.path == "/ws":
            query_params = parse_qs(parsed.query)
            
            # wsrouter.py line 83: check auth parameter
            auth_token = query_params.get("auth", [""])[0]
            
            if auth_token != CSRF_TOKEN:
                self.send_error(403, "Forbidden")
                logger.info("WebSocket rejected: invalid auth token (got: %s)", auth_token)
                return
            
            # Check WebSocket upgrade headers
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self.send_error(400, "Bad Request: Not a WebSocket upgrade")
                return
            
            ws_key = self.headers.get("Sec-WebSocket-Key")
            if not ws_key:
                self.send_error(400, "Bad Request: Missing Sec-WebSocket-Key")
                return
            
            # Send WebSocket upgrade response
            accept = ws_expected_accept(ws_key)
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            
            logger.info("WebSocket handshake completed")
            
            # Handle WebSocket connection
            handle_websocket_connection(
                self.request,
                self.client_address,
                self.config
            )
            return

        if parsed.path == "/plugins":
            # Placeholder for future /plugins endpoint
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            demo_hash = "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"
            plugins = [{"id": 42,
                        "name": "Example Plugin",
                        "version": "1.0.0",
                        "description": "This is a mock plugin.",
                        "author": "John Doe",
                        "versions": [{"name": "1.0.0",
                                      "hash": demo_hash,
                                      "artifact": "http://{}:{}/artifacts/{}.zip".format(
                                          self.server.server_address[0],
                                          self.server.server_address[1],
                                          demo_hash
                                      ),
                                      "created": "2024-01-01T00:00:00Z",
                                      "downloads": 42,
                                      "updates": 0}]}]
            self.wfile.write(json.dumps(plugins).encode("utf-8"))
            return

        if parsed.path.startswith("/artifacts/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            # Send empty zip file content
            self.wfile.write(b"PK\x05\x06" + b"\x00" * 18)
            return

        self.send_error(404, "Not Found")


def run_server(
    host: str = "127.0.0.1",
    port: int = 1337,
    auto_confirm: bool = False,
    simulate_error: bool = False
) -> None:
    """Run the mock Decky Loader backend server.
    
    Args:
        host: Host address to bind to.
        port: Port number to bind to.
        auto_confirm: If True, auto-confirm plugin installations without prompt.
        simulate_error: If True, simulate installation errors.
    """
    MockDeckyHTTPHandler.config = {
        "auto_confirm": auto_confirm,
        "simulate_error": simulate_error
    }
    
    server = ThreadingHTTPServer((host, port), MockDeckyHTTPHandler)
    
    logger.info("Mock Decky Loader Backend Server")
    logger.info("Based on: SteamDeckHomebrew/decky-loader @ 9f586a1b")
    logger.info("Listening: %s:%s", host, port)
    logger.info("Token endpoint: http://%s:%s/auth/token", host, port)
    logger.info("WebSocket endpoint: ws://%s:%s/ws?auth={token}", host, port)
    logger.info("Current CSRF token: %s", CSRF_TOKEN)
    logger.info("Config: auto_confirm=%s simulate_error=%s", auto_confirm, simulate_error)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mock Decky Loader Backend (strictly follows real implementation)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("-p", "--port", type=int, default=1337, help="Bind port")
    parser.add_argument("--auto-confirm", action="store_true",
                        help="Auto-confirm plugin installs (skip prompt)")
    parser.add_argument("--simulate-error", action="store_true",
                        help="Simulate installation errors")
    args = parser.parse_args()
    
    run_server(args.host, args.port, args.auto_confirm, args.simulate_error)
