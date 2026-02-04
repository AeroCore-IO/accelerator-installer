# Decky Installer

A local mirror version of the Decky Installer for Steam Deck. This repository allows users to install Decky plugins without relying on the official Decky Installer servers.

## Features

- Local hosting of Decky Installer files
- Easy installation of Decky plugins
- No dependency on external servers
- **Custom store configuration support** - Configure and use custom plugin store URLs

## Usage

### Basic Plugin Installation

1. Download the `user_install_script.sh` or the `decky_installer.desktop` file from the releases section.
2. Place the downloaded file in a convenient location on your Steam Deck.
3. Run the script or launch the desktop file to start the Decky Installer.

### Custom Store Configuration

The installer now supports configuring custom plugin store URLs:

#### Configure a Custom Store URL
```bash
python3 decky_client.py --configure-store "https://your-custom-store.com/plugins"
```

#### Get the Currently Configured Store URL
```bash
python3 decky_client.py --get-store
```

#### Install from a Custom Store
```bash
python3 decky_client.py --target-id 42 --store-url "https://your-custom-store.com/plugins"
```

## Mock Server for Testing

This repository includes a mock Decky Loader server for testing purposes:

### Start the Mock Server
```bash
python3 mock_decky_server.py --auto-confirm
```

### Test with the Mock Server
```bash
python3 decky_client.py --target-id 42
```

The mock server implements the following Decky Loader backend routes:
- `utilities/ping` - Health check
- `utilities/install_plugin` - Plugin installation
- `utilities/confirm_plugin_install` - Confirm installation
- `utilities/cancel_plugin_install` - Cancel installation
- `utilities/settings/get` - Get configuration settings
- `utilities/settings/set` - Set configuration settings


