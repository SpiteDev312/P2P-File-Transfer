# P2P File Transfer

**A lightweight peer-to-peer file transfer tool for Windows, built with C++17.**

Transfer files and entire folders directly between computers using TCP. No cloud storage or account required.

## Features

- Direct computer-to-computer connection
- Individual file transfer
- Full folder transfer with subdirectory preservation
- Real-time file transfer progress
- TCP communication using Winsock2
- Automatic received folder creation
- Duplicate filename protection

## Requirements

- Windows 10/11
- Visual Studio 2022
- C++17 compatible compiler

## Build

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/P2P-File-Transfer.git
```

Run the build script:

```bat
build_release.bat
```

Launch `P2PTransfer.exe` after compilation.

## Usage

**1. Start the Server**

Select Server mode on the first computer.

**2. Connect the Client**

Select Client mode on the second computer and enter the server's IPv4 address.

**3. Transfer Files**

| Command | Description |
|---|---|
| `/send "file_path"` | Send a file |
| `/sendfolder "folder_path"` | Send a folder |
| `/quit` | Disconnect |

Example:

```text
/sendfolder "D:\Unreal Projects\TestGamePlayMap"
```

Received files are saved in the `received` directory.

## Internet Connection

For remote connections, use a VPN solution such as [Tailscale](https://tailscale.com/) to connect both computers.

Default TCP port: `5000`

## Security Notice

This project currently does not include built-in encryption, authentication, or file integrity verification. Use trusted networks only. Do not expose it directly to the public internet.

## Roadmap

- [ ] End-to-end encryption
- [ ] Device authentication
- [ ] Resume interrupted transfers
- [ ] Transfer speed display
- [ ] Multiple connections
- [ ] Graphical user interface

## Contributing

Bug reports, suggestions, and pull requests are welcome!

## License

MIT License (planned).

---

**If you find this project useful, consider giving it a ⭐!**

Built with C++17 and Windows Winsock2.
