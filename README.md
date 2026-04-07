# Albion Packet Studio v2.4.1

A packet analysis and network inspection tool for Albion Online built with Python, and some dependencies. Captures, decodes, and visualizes Photon protocol traffic in real time. Includes a built-in radar overlay, player tracker, market scanner, and a set of client-side performance tweaks.

<img width="1920" height="1031" alt="1" src="https://github.com/user-attachments/assets/dcaa794b-d315-4f01-9fc0-f9a877ea306a" />


## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Photon Protocol](#photon-protocol)
- [Modules](#modules)
  - [Packet Sniffer](#packet-sniffer)
  - [Decoder](#decoder)
  - [Radar](#radar)
  - [FPS Boost](#fps-boost)
  - [Player Tracker](#player-tracker)
  - [Market](#market)
  - [Settings](#settings)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)

---

## Overview

Albion Online communicates between client and server using the Photon networking engine over UDP port 5056. Every action a player performs (movement, attacks, gathering, trading, entering dungeons) is serialized into Photon operation requests and events, encrypted with AES-256, and sent as UDP datagrams.

This tool sits between the client and the network layer. It captures raw UDP traffic on the configured interface, strips the Photon transport headers, decrypts the payload, and deserializes the operation codes and their parameters into a human-readable structure. No memory injection, no code modification, no proxy. It is a passive listener.

---

## How It Works

The capture pipeline works in the following order:

```
Network Interface (Npcap/WinPcap)
        |
        v
UDP Filter (port 5056)
        |
        v
Photon Header Parser
   - PeerId, CRC flag, command count, timestamp, challenge
        |
        v
Command Extraction
   - Reliable, Unreliable, Fragment, Ack
        |
        v
AES-256 Decryption (session key)
        |
        v
Operation Deserializer
   - OpCode mapping (Move, Attack, Harvest, CastSpell...)
   - Parameter extraction (position, speed, direction, target)
        |
        v
UI Display (tables, radar, alerts)
```

The tool uses raw socket capture or Npcap to grab packets at the driver level. Each packet is filtered by destination/source port, then passed through the Photon protocol parser. The parser handles the Photon header format, extracts individual commands from the payload, and passes them to the decryption layer. After decryption, operation codes are matched against a known mapping table and parameters are deserialized from the Photon binary format into typed values (int32, float, string, byte arrays, vectors).

---

## Photon Protocol

Albion Online uses Exit Games Photon as its networking layer. The protocol is binary, compact, and operates primarily over UDP.

### Packet Structure

```
+------------------+------------------+------------------+
| Photon Header    | Command Header   | Payload          |
| (12 bytes)       | (12 bytes each)  | (variable)       |
+------------------+------------------+------------------+
```

**Photon Header fields:**
| Field        | Size    | Description                              |
|--------------|---------|------------------------------------------|
| PeerId       | 2 bytes | Client session identifier                |
| CrcEnabled   | 1 byte  | Whether CRC32 validation is active       |
| CommandCount | 1 byte  | Number of commands in this packet        |
| Timestamp    | 4 bytes | Server-relative timestamp in ms          |
| Challenge    | 4 bytes | Connection handshake challenge value     |

**Command types:**
| Type ID | Name                | Description                          |
|---------|---------------------|--------------------------------------|
| 1       | Acknowledge         | Confirms receipt of reliable command |
| 2       | Connect             | Initial connection request           |
| 3       | VerifyConnect       | Connection verification response     |
| 4       | Disconnect          | Clean session teardown               |
| 5       | Ping                | Latency measurement                  |
| 6       | SendReliable        | Guaranteed delivery operation        |
| 7       | SendUnreliable      | Best-effort operation                |
| 8       | SendFragment        | Part of a fragmented message         |

### Encryption

After the initial handshake, all SendReliable and SendUnreliable payloads are encrypted with AES-256 in CBC mode. The session key is derived during the connection establishment phase. The tool extracts this key from the handshake sequence and uses it for all subsequent decryption within the session.

### Operation Codes

Every game action maps to a numeric OpCode. Some known mappings:

| OpCode | Operation       | Direction | Description                        |
|--------|-----------------|-----------|------------------------------------|
| 1      | Ping            | OUT       | Client keepalive                   |
| 2      | Login           | OUT       | Authentication request             |
| 3      | CreateCharacter | OUT       | Character creation                 |
| 18     | Move            | BOTH      | Player/entity position update      |
| 19     | CastSpell       | BOTH      | Ability cast with target info      |
| 23     | Attack          | BOTH      | Auto-attack on target              |
| 42     | Harvest         | OUT       | Gathering resource node            |
| 51     | Mount           | OUT       | Mount/dismount toggle              |
| 62     | ChangeCluster   | IN        | Zone transition notification       |
| 75     | JoinParty       | BOTH      | Party join request/event           |
| 78     | LeaveParty      | BOTH      | Party leave notification           |
| 83     | PickupLoot      | OUT       | Loot collection                    |
| 94     | OpenBank        | OUT       | Bank access request                |
| 107    | TradeRequest    | BOTH      | Player-to-player trade             |
| 120    | ChatMessage     | BOTH      | Chat send/receive                  |

---

## Modules

### Packet Sniffer

<img width="1920" height="1031" alt="1" src="https://github.com/user-attachments/assets/f7c8bb3f-a8f3-43db-938b-cc8d97d61690" />


The primary module. Displays a live scrolling table of all captured packets with the following columns:

- **Time** - capture timestamp (HH:MM:SS)
- **Dir** - direction indicator (IN = server to client, OUT = client to server), color-coded green/yellow
- **OpCode** - numeric operation code, highlighted in purple
- **Operation** - human-readable operation name
- **Size** - packet payload size in bytes

The left panel provides filtering controls:

- Toggle incoming/outgoing packets independently
- Filter by specific OpCode value
- Enable/disable individual operation types (Move, Attack, Harvest, CastSpell, Mount, ChatMessage, JoinParty, TradeRequest)
- Live statistics: total packets captured, capture rate (pkt/s), session uptime
- Export the current capture log to CSV for external analysis

### Decoder

<img width="1920" height="999" alt="2" src="https://github.com/user-attachments/assets/94f13450-7af1-432a-ac5b-f82acd73f7b1" />


Manual packet inspection and decoding. Accepts raw hex input and parses it through the full Photon protocol stack.

**Left panel:**
- Hex input area for pasting raw packet data
- "Decode Photon" button for standard decoding
- "Auto-Detect" for automatic protocol detection
- Protocol selection: Photon (UDP), Photon (Reliable), WebSocket, Raw TCP
- Encryption mode: AES-256, Blowfish, None
- Manual encryption key input (hex format)

**Right panel:**
- Tree-view breakdown of the decoded packet structure
- Nested hierarchy: PhotonHeader > ReliableCommand > OperationRequest > Parameters
- Color-coded values: header fields in teal, operation codes in yellow, parameter values in purple

This module is useful for offline analysis of saved packet dumps, debugging custom protocol implementations, or verifying the correctness of captured data.

### Radar

<img width="1920" height="999" alt="3" src="https://github.com/user-attachments/assets/aa0f1fb5-80c2-4c82-ad92-d70c1420c679" />


A 2D top-down radar view showing entities in the current zone relative to the player's position.

**Entity types displayed:**
- **Players** (red dots) - other player characters with name labels
- **Mobs** (orange dots) - hostile and passive creatures
- **Resources** (teal dots) - gatherable nodes with tier labels (T6 Ore, T7 Hide, etc.)
- **Chests** (gold dots) - lootable containers
- **Dungeons** (purple dots) - dungeon entrance markers

**Settings panel:**
- Toggle visibility per entity type
- Range slider (30-300 units) - controls the visible radius
- Opacity slider (10-100%) - overlay transparency
- Scale slider (50-200%) - zoom level
- Custom background color picker

**Alert system:**
- Player proximity alert with configurable distance threshold
- Resource spawn alert
- Distance slider for trigger radius (10-200 units)

The radar canvas renders a grid overlay with concentric range circles and crosshair centered on the player's position. Entity positions are calculated from the coordinate data extracted from Move operation packets.

### FPS Boost

<img width="1920" height="1000" alt="4" src="https://github.com/user-attachments/assets/9f8ba1c3-a931-4ad0-ab65-61f16a6638b6" />


Client-side performance optimization module. Modifies rendering parameters and system configuration to improve frame rate.

**Performance Tweaks:**
- Disable grass rendering
- Reduce particle effect density
- Disable shadow maps
- Switch to low-quality texture mipmaps
- Disable weather particle systems
- Reduce view/draw distance
- Disable idle character animations
- Skip intro/splash videos on launch

**Process Management:**
- Priority level: Normal, Above Normal, High, Realtime
- CPU affinity: All Cores, Performance Only, Single Core

**Memory Management:**
- Automatic standby list clearing at configurable intervals (30-600 seconds)
- Large page memory support toggle

**System Monitor (right panel):**
- Real-time CPU, RAM, GPU, and VRAM usage bars with percentage overlays
- FPS graph with current, average, and 1% low values plotted over time
- Network latency graph showing ping, jitter, and packet loss metrics

### Player Tracker

<img width="1920" height="996" alt="5" src="https://github.com/user-attachments/assets/58fc3e1c-cb00-461b-ac4b-aa11aefc58f7" />


Monitors and displays information about players detected in the current zone.

**Tracking options:**
- Search by player name
- Toggle tracking for guild members, alliance members, hostile players
- Auto-screenshot on kill events

**Watchlist:**
- Persistent player watchlist with guild tag display
- Add/remove players to track across sessions

**Nearby Players table:**
| Column   | Description                                      |
|----------|--------------------------------------------------|
| Name     | Character name (color-coded by threat level)     |
| Guild    | Guild tag                                        |
| Alliance | Alliance tag                                     |
| IP       | Item Power score (gear score), highlighted       |
| Weapon   | Currently equipped main-hand weapon              |
| Dist     | Distance from player in meters                   |

Player names are color-coded: red for hostile guilds/alliances, purple for neutral/friendly. Item Power values are highlighted in yellow for quick threat assessment.

### Market

<img width="1920" height="996" alt="6" src="https://github.com/user-attachments/assets/f6456bff-bf6c-45ed-95b6-ca21f514e7a8" />


Intercepts and displays market order data from the game's trading system.

**Scanner filters:**
- City: Caerleon, Bridgewatch, Fort Sterling, Lymhurst, Martlock, Thetford, Black Market
- Category: Weapons, Armor, Accessories, Resources, Consumables, Mounts
- Tier: T4 through T8
- Enchantment: .0, .1, .2, .3

**Features:**
- Scan active buy/sell orders
- "Find Flips" - identifies items with profitable buy-sell spreads across cities
- Profit alert threshold slider (1-100% minimum margin)
- Sound and desktop notification support for price triggers

**Price Table columns:**
| Column | Description                                       |
|--------|---------------------------------------------------|
| Item   | Item name with tier prefix                        |
| Buy    | Lowest buy order price (purple)                   |
| Sell   | Lowest sell order price (teal)                    |
| Profit | Absolute profit margin (green)                    |
| Margin | Percentage margin (green if >15%, yellow if less) |

### Settings

<img width="1920" height="1001" alt="7" src="https://github.com/user-attachments/assets/d4330f74-4301-4d91-81f0-9dba33bb44c0" />

Global application configuration split into two panels.

**Left panel:**
- **General**: startup behavior, auto-connect, update checks, language selection (English, Russian, German, Portuguese, Chinese)
- **Capture**: driver selection (Npcap, WinPcap, Raw Socket, WinDivert), buffer size, promiscuous mode
- **Logging**: log level (None, Errors Only, Info, Debug, Verbose), file output toggle, log directory path
- **Hotkeys**: configurable keybinds for overlay toggle (F2), start/stop capture (F5), screenshot (F9)

**Right panel:**
- **Theme & Appearance**: theme presets (Dark Abyss, Midnight Blue, Cyberpunk, Nord, Dracula), UI scale, font size, animation toggle
- **Notifications**: sound alerts with volume control, desktop notifications, taskbar flash
- **Advanced**: hardware acceleration, multi-threaded decoding with thread count, plugin system toggle

---

## Installation

Windows only: install [Npcap](https://npcap.com/) for packet capture functionality.

## Usage



1. Select the network interface your game traffic passes through (Ethernet, Wi-Fi, etc.)
2. Verify the port is set to 5056 (default Albion Online game port)
3. Click **Connect** to begin packet capture
4. Switch between tabs to access different modules
5. Click **Disconnect** to stop the capture session

The status bar at the bottom displays: connection state, total packets captured, current capture rate, and session uptime.

## Configuration

All settings are accessible through the Settings tab. Changes are applied immediately. Use "Save Settings" to persist configuration across sessions. "Reset All" reverts to factory defaults.

Key configuration parameters:

| Parameter         | Default  | Description                              |
|-------------------|----------|------------------------------------------|
| Interface         | Ethernet | Network adapter for capture              |
| Port              | 5056     | UDP port to filter                       |
| Capture Driver    | Npcap    | Packet capture backend                   |
| Buffer Size       | 4096 KB  | Capture ring buffer size                 |
| Log Level         | Info     | Logging verbosity                        |
| Theme             | Dark Abyss | UI color scheme                        |
| Process Priority  | High     | Game process priority class              |

## Requirements

- Windows 10/11
- Npcap (for live packet capture)

## Disclaimer

This software is provided for educational and research purposes. Use it at your own risk. The authors take no responsibility for any consequences of using this tool. Make sure to comply with the game's Terms of Service.
