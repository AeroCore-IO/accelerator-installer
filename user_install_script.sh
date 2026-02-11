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

if [ "$SKIP_DECKY_INSTALL" != true ]; then
  if ! curl -fsSL "https://${DECKY_MIRROR_HOST}/SteamDeckHomebrew/decky-installer/releases/latest/download/user_install_script.sh" \
    | sed -E \
        -e "s#github\.com#${DECKY_MIRROR_HOST}#g" \
        -e "s#api\.github\.com#api.${DECKY_MIRROR_HOST}#g" \
        -e "s#raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/#${DECKY_MIRROR_HOST}/\1/\2/plain/#g" \
    > "${tmp_script}"; then
    echo "Failed to download or rewrite the official installer script." >&2
    exit 1
  fi

  # The official installer may exit with a non-zero code even when it succeeds.
  # Do not abort our script here; verify via systemd instead.
  set +e
  bash "${tmp_script}"
  installer_status=$?
  set -e

  if systemctl is-active --quiet plugin_loader.service 2>/dev/null; then
    echo "Decky Loader install completed (installer exit code: ${installer_status})."
  else
    echo "Decky Loader install did not complete successfully (installer exit code: ${installer_status})." >&2
    exit 1
  fi
fi

# Download and verify Decky Loader client (mirror-hosted).
decky_client="/tmp/decky_client.py"
decky_client_checksum="/tmp/decky_client.py.sha256"

# Download the client script
if ! curl -fsSL "https://${DECKY_MIRROR_HOST}/AeroCore-IO/decky-installer/releases/latest/download/decky_client.py" -o "${decky_client}"; then
  echo "Failed to download Decky Loader client script." >&2
  exit 1
fi

# Download the checksum file
if ! curl -fsSL "https://${DECKY_MIRROR_HOST}/AeroCore-IO/decky-installer/releases/latest/download/decky_client.py.sha256" -o "${decky_client_checksum}"; then
  echo "Failed to download checksum file for Decky Loader client." >&2
  exit 1
fi

# Verify the checksum
if ! (cd /tmp && sha256sum -c decky_client.py.sha256); then
  echo "Checksum verification failed for Decky Loader client. File may be compromised." >&2
  rm -f "${decky_client}" "${decky_client_checksum}"
  exit 1
fi

# Configure the custom store URL first to ensure install requests go to the correct store
python3 "${decky_client}" configure-store "https://${DECKY_PLUGIN_MIRROR_HOST}/plugins"

# Install the plugin
python3 "${decky_client}" install \
  --store-url "https://${DECKY_PLUGIN_MIRROR_HOST}/plugins" \
  --target-id "${DECKY_PLUGIN_TARGET_ID}"

# Clean up
rm -f "${decky_client}" "${decky_client_checksum}"
