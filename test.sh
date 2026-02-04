#!/usr/bin/env bash
set -euo pipefail

bash -n user_install_script.sh

python3 mock_decky_server.py </dev/null >> /tmp/mock_decky_server.log 2>&1 &
server_pid=$!
echo "Mock Decky Server is running. Logs are being written to /tmp/mock_decky_server.log"
trap "kill $server_pid" EXIT

python3 decky_client.py
