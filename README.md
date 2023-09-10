# Wireshark Investigators Pack
Custom integrations for investigating packets

This lua script adds a collection of custom commands for investigating network traffic during incident response.

# Prerequisities:
Needs to be running Wireshark 4.2. Some features are only available on Windows.

# Quick Usage
Copy the contents of `wireshark_investigators_pack.lua` into Wireshark's `Tools -> Lua -> Evaluate` text box.

# Installation:
Copy `wireshark_investigators_pack.lua` to your Plugins directory:

On Windows:
* The personal plugin folder is %APPDATA%\Wireshark\plugins.
* The global plugin folder is WIRESHARK\plugins.

On Unix-like systems:
* The personal plugin folder is ~/.local/lib/wireshark/plugins.

Source: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
