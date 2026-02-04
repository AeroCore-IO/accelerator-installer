import argparse
import asyncio
import base64
import json
import os
import struct
import sys
import urllib.request
from typing import Any, Dict, List, Optional

# Decky Loader Message Types
CALL = 0
REPLY = 1
ERROR = -1
EVENT = 3

# Default store URL
DEFAULT_STORE_URL = "https://plugins.deckbrew.xyz/plugins"


def log(*args: Any) -> None:
    """Print formatted logs to stderr."""
    print("[DeckyInstaller]", *args, file=sys.stderr, flush=True)


class DeckyClient:
    """
    A robust client for Decky Loader using asyncio streams.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1337):
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.msg_id = 0

    async def get_token(self) -> str:
        """Fetch the CSRF token via HTTP GET."""
        url = f"http://{self.host}:{self.port}/auth/token"
        # Using a context manager for the request
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.read().decode().strip()


    async def connect(self, token: str) -> None:
        """Connect and perform WebSocket handshake."""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        # Build handshake
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET /ws?auth={token} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.writer.write(handshake.encode())
        await self.writer.drain()

        # Read response headers (terminated by \r\n\r\n)
        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = await self.reader.read(1024)
            if not chunk:
                raise ConnectionError("Server closed connection during handshake")
            header_data += chunk

        if b"101 Switching Protocols" not in header_data:
            raise RuntimeError(f"Handshake failed: {header_data.decode(errors='ignore')}")

        # Note: Any data after \r\n\r\n is the start of the first WS frame
        # asyncio.StreamReader handles the internal buffer automatically.

    async def send(self, msg_type: int, method: str, args: List[Any]) -> None:
        """Send a masked WebSocket text frame."""
        self.msg_id += 1

        message_dict = {
            "type": msg_type,
            "id": self.msg_id,
            "route": method,
            "args": args,
        }
        payload = json.dumps(message_dict).encode()
        length = len(payload)

        # Header: FIN=1, Opcode=1 (Text)
        frame = bytearray([0x81])

        if length < 126:
            frame.append(length | 0x80)
        elif length < 65536:
            frame.append(126 | 0x80)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(127 | 0x80)
            frame.extend(struct.pack("!Q", length))

        # Client must mask data
        mask = os.urandom(4)
        frame.extend(mask)
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame.extend(masked_payload)

        self.writer.write(frame)
        await self.writer.drain()

    async def recv(self) -> Optional[Dict[str, Any]]:
        """Receive and parse one WebSocket text frame."""
        try:
            # Read first 2 bytes: Opcode and Length
            head = await self.reader.readexactly(2)
            # opcode = head[0] & 0x0F
            has_mask = head[1] & 0x80
            length = head[1] & 0x7F

            if length == 126:
                ext_len = await self.reader.readexactly(2)
                length = struct.unpack("!H", ext_len)[0]
            elif length == 127:
                ext_len = await self.reader.readexactly(8)
                length = struct.unpack("!Q", ext_len)[0]

            if has_mask:
                mask = await self.reader.readexactly(4)

            payload_raw = await self.reader.readexactly(length)

            if has_mask:
                payload_raw = bytes(b ^ mask[i % 4] for i, b in enumerate(payload_raw))

            return json.loads(payload_raw.decode())
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def close(self) -> None:
        """Send a WebSocket close frame and close the stream."""
        if not self.writer:
            return
        try:
            # FIN=1, opcode=8 (Close), masked payload with status 1000
            payload = struct.pack("!H", 1000)
            frame = bytearray([0x88, 0x80 | len(payload)])
            mask = os.urandom(4)
            frame.extend(mask)
            masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            frame.extend(masked_payload)
            self.writer.write(frame)
            await self.writer.drain()
        except Exception:
            pass
        finally:
            self.writer.close()
            await self.writer.wait_closed()


async def run_installer(target_id: int, store_url: str) -> None:
    """Installation workflow."""
    client = DeckyClient()
    success = False
    error: Optional[BaseException] = None
    try:
        log(f"Contacting Mock Server at {client.host}:{client.port}...")
        token = await client.get_token()
        await client.connect(token)

        log(f"Connection established. Fetching plugin metadata for ID: {target_id}")
        with urllib.request.urlopen(store_url, timeout=10) as response:
            store_raw = response.read().decode()
        plugins = json.loads(store_raw)
        target = next((p for p in plugins if int(p.get("id")) == int(target_id)), None)
        if not target:
            raise RuntimeError(f"plugin id {target_id} not found")

        plugin_name = target.get("name") or f"plugin-{target_id}"
        versions = target.get("versions") or []
        if not versions:
            raise RuntimeError("store entry missing versions")

        latest = sorted(versions, key=lambda v: (v.get("name") or ""))[-1]
        version_name = latest.get("name") or "dev"
        artifact_url = latest.get("artifact") or ""
        hash_ = latest.get("hash") or ""
        if not artifact_url:
            raise RuntimeError("latest version missing artifact URL")

        log(f"Installing {plugin_name} v{version_name}")
        await client.send(CALL, "utilities/install_plugin",
                          [artifact_url, plugin_name, version_name, hash_, 0])

        while True:
            msg = await client.recv()
            if msg is None:
                log("Connection closed by server.")
                break

            m_type = msg.get("type")

            if m_type == EVENT and msg.get("event") == "loader/add_plugin_install_prompt":
                m_args = msg.get("args", [])
                if len(m_args) < 3:
                    log(f"Invalid install prompt args: {m_args}")
                    continue
                request_id = m_args[2]
                log("Prompt received, sending confirmation...")
                await client.send(CALL, "utilities/confirm_plugin_install",
                                  [request_id])

            elif m_type == EVENT and msg.get("event") == "loader/plugin_download_finish":
                log(f"Installation successful: {msg.get('args')}")
                success = True
                break

            elif m_type == REPLY:
                log(f"Server reply: {msg.get('result')}")

            elif m_type == ERROR:
                log(f"Server error: {msg.get('error')}")

    except Exception as e:
        log(f"Error: {e}")
        error = e
    finally:
        await client.close()

    if error:
        raise error
    if not success:
        raise RuntimeError("Installation did not complete successfully")


async def configure_store_url(store_url: str) -> None:
    """Configure custom store URL in Decky settings."""
    client = DeckyClient()
    try:
        log(f"Connecting to Decky server at {client.host}:{client.port}...")
        token = await client.get_token()
        await client.connect(token)

        log(f"Setting custom store URL: {store_url}")
        await client.send(CALL, "utilities/settings/set", ["store_url", store_url])
        
        # Wait for reply
        msg = await client.recv()
        if msg is None:
            raise RuntimeError("Connection closed by server")
        
        m_type = msg.get("type")
        
        if m_type == REPLY:
            log(f"Store URL configured successfully: {msg.get('result')}")
        elif m_type == ERROR:
            log(f"Server error: {msg.get('error')}")
            raise RuntimeError(f"Failed to set store URL: {msg.get('error')}")
        
    except Exception as e:
        log(f"Error: {e}")
        raise
    finally:
        await client.close()


async def get_store_url() -> str:
    """Get the configured custom store URL from Decky settings."""
    client = DeckyClient()
    try:
        log(f"Connecting to Decky server at {client.host}:{client.port}...")
        token = await client.get_token()
        await client.connect(token)

        log("Getting configured store URL...")
        await client.send(CALL, "utilities/settings/get", ["store_url", DEFAULT_STORE_URL])
        
        # Wait for reply
        msg = await client.recv()
        if msg is None:
            raise RuntimeError("Connection closed by server")
        
        m_type = msg.get("type")
        
        if m_type == REPLY:
            store_url = msg.get('result')
            log(f"Current store URL: {store_url}")
            return store_url
        elif m_type == ERROR:
            log(f"Server error: {msg.get('error')}")
            raise RuntimeError(f"Failed to get store URL: {msg.get('error')}")
        
        raise RuntimeError("Unexpected response type")
        
    except Exception as e:
        log(f"Error: {e}")
        raise
    finally:
        await client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Decky Loader Client - Manage plugins and settings",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Install subcommand
    install_parser = subparsers.add_parser(
        "install",
        help="Install a plugin from the store"
    )
    install_parser.add_argument(
        "--store-url",
        default="http://127.0.0.1:1337/plugins",
        help="Plugin store URL to fetch plugins from (default: http://127.0.0.1:1337/plugins)"
    )
    install_parser.add_argument(
        "--target-id",
        type=int,
        default=42,
        help="Plugin ID to install (default: 42)"
    )
    
    # Configure store subcommand
    config_parser = subparsers.add_parser(
        "configure-store",
        help="Configure custom store URL in Decky settings"
    )
    config_parser.add_argument(
        "url",
        help="Custom store URL to configure"
    )
    
    # Get store subcommand
    subparsers.add_parser(
        "get-store",
        help="Get the configured custom store URL"
    )
    
    args = parser.parse_args()
    
    # Execute based on subcommand
    if args.command == "install":
        asyncio.run(run_installer(
            target_id=args.target_id,
            store_url=args.store_url
        ))
    elif args.command == "configure-store":
        asyncio.run(configure_store_url(args.url))
    elif args.command == "get-store":
        asyncio.run(get_store_url())
    else:
        parser.print_help()
        sys.exit(1)
