#!/usr/bin/env bash
set -euo pipefail

# Hardcoded mirror host for GitHub/API/RAW substitutions
DECKY_MIRROR_HOST="__DECKY_MIRROR_HOST__"
DECKY_PLUGIN_MIRROR_HOST="__DECKY_PLUGIN_MIRROR_HOST__"
DECKY_PLUGIN_TARGET_ID="__DECKY_PLUGIN_ID__"

# Check if Decky Loader is already installed and running on SteamOS
echo "Checking if Decky Loader is already installed and running..."
if systemctl is-active --quiet plugin_loader.service 2>/dev/null; then
  echo "Decky Loader (plugin_loader.service) is already running. Skipping Decky Loader installation."
  SKIP_DECKY_INSTALL=true
else
  echo "Decky Loader is not running or not installed. Proceeding with installation."
  SKIP_DECKY_INSTALL=false
fi

# Download the official installer script, rewrite domains to the mirror, then execute.
# This keeps the original installer logic intact while swapping network endpoints.
tmp_script="/tmp/decky_user_install_script.sh"

if [ "$SKIP_DECKY_INSTALL" = false ]; then
  if ! curl -fsSL "https://${DECKY_MIRROR_HOST}/SteamDeckHomebrew/decky-installer/releases/latest/download/user_install_script.sh" \
    | sed -E \
        -e "s#github\.com#${DECKY_MIRROR_HOST}#g" \
        -e "s#api\.github\.com#api.${DECKY_MIRROR_HOST}#g" \
        -e "s#raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/#${DECKY_MIRROR_HOST}/\1/\2/plain/#g" \
    > "${tmp_script}"; then
    echo "Failed to download or rewrite the official installer script." >&2
    exit 1
  fi

  bash "${tmp_script}"
fi

# Download and run decky plugin installer helper (mirror-hosted).
plugin_installer="/tmp/decky_plugin_installer.py"
if curl -fsSL "https://${DECKY_MIRROR_HOST}/AeroCore-IO/decky-installer/releases/latest/download/decky_plugin_installer.py" -o "${plugin_installer}"; then
  python3 "${plugin_installer}" \
    --store-url "https://${DECKY_PLUGIN_MIRROR_HOST}/plugins" \
    --target-id "${DECKY_PLUGIN_TARGET_ID}"
else
  echo "Failed to download decky installer helper script." >&2
  exit 1
fi
