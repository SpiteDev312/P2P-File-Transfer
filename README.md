# P2P File Transfer

**A lightweight, direct file transfer application for Windows, written in C++17.**

P2P File Transfer allows two computers to connect directly over a TCP connection and exchange files or entire folders without relying on cloud storage services.

Send individual files, transfer complete project folders, and monitor transfer progress from a simple command-line interface.

## Features

- **Direct P2P Connection** — Connect two computers using an IPv4 address.
- **File Transfer** — Send individual files of different types.
- **Folder Transfer** — Send entire folders, including their files and subdirectories.
- **Progress Display** — Monitor file transfer progress in the console.
- **TCP Communication** — Uses Windows Winsock2 and TCP sockets.
- **64 KB Transfer Buffer** — Transfers file contents in manageable chunks.
- **Automatic Folder Creation** — Received folders are recreated with their directory structure.
- **Duplicate Name Handling** — Avoids overwriting existing received files and folders.
- **Simple CLI** — No complicated interface or account registration required.

## How It Works

The application uses a server/client connection model.

1. One computer starts in **Server** mode and waits for a connection.
2. The second computer starts in **Client** mode and enters the server's IPv4 address.
3. Once connected, both computers can send and receive files.
4. Received files and folders are saved inside the `received` directory.

## Getting Started

### Requirements

- Windows 10 or Windows 11
- Visual Studio 2022 (or compatible MSVC compiler)
- Desktop development with C++ workload
- C++17 support

### Build from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/YOUR_USERNAME/P2P-File-Transfer.git
   ```

2. Open the project directory.

3. Run the provided build script:

   ```bat
   build_release.bat
   ```

4. If compilation succeeds, launch:

   ```text
   P2PTransfer.exe
   ```

> Make sure your Visual Studio C++ build tools are installed and configured correctly.

## Usage

### 1. Start the Server

On the first computer, launch the application and select:

```text
[1] Server - Dosya bekle
```

The application listens on TCP port `5000`.

### 2. Connect as a Client

On the second computer, launch the application and select:

```text
[2] Client - IP adresine baglan
```

Enter the server computer's IPv4 address.

After a successful connection, you should see:

```text
[CONNECTED] Baglanti basarili!
```

### 3. Available Commands

| Command | Description |
|---|---|
| `/send "file_path"` | Send an individual file |
| `/sendfolder "folder_path"` | Send an entire folder |
| `/quit` | Close the connection |

### Send a File

```text
/send "C:\Users\User\Desktop\example.zip"
```

### Send an Entire Folder

```text
/sendfolder "D:\Unreal Projects\TestGamePlayMap"
```

The folder structure is preserved on the receiving computer.

### Example Received Structure

```text
received/
└── TestGamePlayMap/
    ├── Config/
    ├── Content/
    │   ├── Maps/
    │   ├── Materials/
    │   └── Blueprints/
    ├── Source/
    └── TestGamePlayMap.uproject
```

The example above illustrates a possible Unreal Engine project structure. Actual contents depend on the folder being transferred.

## Connecting Over the Internet

The application uses direct TCP connections.

For computers on the same local network, use the server computer's local IPv4 address.

For computers in different locations, you can use a VPN network such as **Tailscale**:

1. Install Tailscale on both computers.
2. Connect both devices to the same Tailscale network.
3. Find the server computer's Tailscale IPv4 address.
4. Enter that address in Client mode.

The application itself does not provide NAT traversal or public relay functionality.

## Network Configuration

Default connection settings:

| Setting | Value |
|---|---|
| Protocol | TCP |
| Port | `5000` |
| Address format | IPv4 |
| Transfer buffer | 64 KB |
| Platform | Windows |

Windows Firewall may ask for network access. Allow access only on networks you trust.

## Project Structure

```text
P2P-File-Transfer/
│
├── main.cpp
├── build_release.bat
├── README.md
├── LICENSE
└── .gitignore
```

## Security Notice

This project is an early-stage file transfer utility.

- The application does not implement its own encryption.
- There is no user authentication or access-control system.
- Received files are not verified with cryptographic checksums.
- Only connect to computers and networks you trust.

For transfers over the internet, use a trusted encrypted VPN such as Tailscale. Do not expose the application directly to the public internet without adding appropriate security protections.

**Do not use this project to transfer sensitive or confidential data in its current state.**

## Current Limitations

This is an actively developing project. Some features are not implemented yet:

- End-to-end encryption inside the application
- Authentication and pairing
- Resume interrupted transfers
- Transfer speed statistics (MB/s)
- Multiple simultaneous connections
- Graphical user interface
- File integrity verification

## Roadmap

Planned improvements:

- [ ] End-to-end encryption
- [ ] Device authentication and pairing
- [ ] Resume interrupted transfers
- [ ] Real-time transfer speed display
- [ ] Overall folder transfer progress
- [ ] Multiple device support
- [ ] File integrity verification
- [ ] Graphical user interface
- [ ] Configurable network port
- [ ] Improved error handling

## Contributing

Contributions, bug reports, and feature suggestions are welcome!

If you find a bug or have an idea for improvement:

1. Open an issue.
2. Describe the problem or proposed feature.
3. Include reproduction steps when reporting a bug.
4. Submit a pull request if you want to contribute code.

## License

This project is intended to be released under the MIT License.

See the `LICENSE` file for details.

---

**If you find this project useful, consider giving it a ⭐ on GitHub!**

Built with C++17 and Windows Winsock2.
