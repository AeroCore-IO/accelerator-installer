#!/usr/bin/env bash
set -euo pipefail

# Hardcoded mirror host for GitHub/API/RAW substitutions
DECKY_MIRROR_HOST="__DECKY_MIRROR_HOST__"

# Download the official installer script, rewrite domains to the mirror, then execute.
# This keeps the original installer logic intact while swapping network endpoints.
tmp_script="/tmp/decky_user_install_script.sh"

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
