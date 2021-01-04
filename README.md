# Wireshark Hunt Pack
Custom integrations for investigating packets

This lua script adds a collection of custom commands for investigating network traffic during incident response.

# Pre-requisities:
Needs to be running Wireshark 3.5.0 (or whichever release has https://gitlab.com/wireshark/wireshark/-/merge_requests/1500 merged)

# Quick Usage
Run wireshark from the CLI as `wireshark -X lua_script:path/to/hunt_pack.lua`

# Installation:
Copy `hunt_pack.lua` to your Plugins directory:

On Windows:
* The personal plugin folder is %APPDATA%\Wireshark\plugins.
* The global plugin folder is WIRESHARK\plugins.

On Unix-like systems:
* The personal plugin folder is ~/.local/lib/wireshark/plugins.

Source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
