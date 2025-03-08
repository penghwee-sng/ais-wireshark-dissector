# AIS Wireshark Dissector

A Wireshark dissector for Automatic Identification System (AIS) messages. This dissector parses NMEA formatted AIS messages, interprets their content, and displays the decoded information in a structured format in Wireshark.

## Features

- Decodes AIS messages from NMEA formatted sentences (`!AIVDM` and `!AIVDO`)
- Supports common AIS message types:
  - Types 1, 2, 3: Position reports (Class A)
  - Type 4: Base station reports
  - Type 5: Static and voyage data
  - Types 18, 19: Position reports (Class B)
  - Type 21: Aid-to-navigation reports
  - Type 24: Static data reports
- Reassembles multi-fragment AIS messages
- Validates NMEA checksums
- Provides detailed information about vessel position, speed, heading, dimensions, etc.
- Works with both UDP and TCP streams
- Uses heuristic dissection to automatically identify AIS data

## Installation

### Windows

1. Find your Wireshark plugins directory:
   - Personal plugins: `%APPDATA%\Wireshark\plugins\` (typically `C:\Users\[Username]\AppData\Roaming\Wireshark\plugins\`)
   - Global plugins: `[Wireshark Install Dir]\plugins\`

2. Copy the `ais_dissector.lua` file into this directory.

3. Restart Wireshark if it's already running.

### Linux/macOS

1. Find your Wireshark plugins directory:
   - Personal plugins: `~/.local/lib/wireshark/plugins/`
   - Global plugins: `/usr/lib/wireshark/plugins/` or `/usr/local/lib/wireshark/plugins/`

2. Copy the `ais_dissector.lua` file into this directory.

3. Restart Wireshark if it's already running.

## Usage

Once installed, the dissector will automatically detect and decode AIS messages in your capture files or live captures.

### Viewing AIS Data

1. Open Wireshark and capture traffic or open a capture file containing AIS messages.
2. AIS messages are typically transmitted on UDP port 10110, though the dissector will try to identify AIS messages on any port using heuristic analysis.
3. Look for packets with the protocol identified as "AIS" in the protocol column.
4. Click on an AIS packet to see the decoded information in the packet details pane.

### Filtering AIS Messages

You can use the following display filters to find specific AIS information:

- `ais` - Show all AIS messages
- `ais.msg_type == 1` - Show only position reports (message type 1)
- `ais.mmsi == 123456789` - Show messages from a specific vessel by MMSI
- `ais.shipname contains "EXAMPLE"` - Show messages from vessels with names containing "EXAMPLE"
- `ais.longitude > 50 && ais.longitude < 55` - Show vessels in specific longitude range
- `ais.sog > 15` - Show vessels traveling faster than 15 knots

### Preferences

Access Wireshark preferences (Edit → Preferences → Protocols → AIS) to configure:

- **Reassemble fragmented messages**: Enable/disable the reassembly of multi-part AIS messages.

## Troubleshooting

- If you don't see the AIS protocol in your capture:
  - Verify that the plugin is installed in the correct directory
  - Check that your capture actually contains NMEA formatted AIS messages
  - Try enabling heuristic dissection in Wireshark preferences

- If multi-part messages aren't being reassembled:
  - Make sure the "Reassemble fragmented messages" preference is enabled
  - Verify that all fragments of the message are present in the capture

## Contributing

Contributions to improve the dissector are welcome! Please feel free to submit pull requests or report any issues you encounter.

## License

This project is available under the GNU General Public License v3.0.
