# P2P File Transfer

A simple peer-to-peer file transfer tool for Windows, written in C++.

Transfer files and folders directly between two computers over TCP.

## Features

- Direct file and folder transfers
- AES-256-GCM encryption
- Transfer speed and progress display
- Folder structure preservation
- No cloud storage required

## Requirements

- Windows 10/11
- Visual Studio 2022
- C++17

## Build

Run `build_release.bat` to compile the application.

## Usage

1. Start the app on both computers.
2. Select Server on one computer.
3. Connect from the other using the server's IP address.
4. Use the following commands:

| Command | Description |
|---|---|
| `/send "path"` | Send a file |
| `/sendfolder "path"` | Send a folder |
| `/quit` | Disconnect |

Received files are saved in the `received` folder.

## License

MIT
