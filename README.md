# SSH Tunnels + Web Proxy GUI

A simple GUI application in **Go** using **Fyne** to manage SSH tunnels, dynamic port forwarding (SOCKS), and optional HTTP/HTTPS proxy support. Supports password/key-based authentication, including 2FA.
[![Build SSH Tunnel GUI App](https://github.com/grayson85/SSHTunnel-WebProxy/actions/workflows/build.yml/badge.svg)](https://github.com/grayson85/SSHTunnel-WebProxy/actions/workflows/build.yml)
---

## Features

- GUI for managing multiple SSH tunnels.
- Local (`-L`), Remote (`-R`), and Dynamic (`-D`) SSH forwarding.
- Optional HTTP/HTTPS proxy for restricted networks.
- Keyboard-interactive 2FA support.
- Persistent configuration stored in `tunnels.json`.
- Visual indicator for running/stopped tunnels.

---

## Compilation

Make sure Go and Fyne dependencies are installed:

```bash
go get fyne.io/fyne/v2
go get golang.org/x/crypto/ssh

````

Compile for Different Platforms

Windows
````
fyne package -os windows -icon Icon.png
````
- Produces a Windows .exe file.
- Make sure your Go environment is set up for Windows compilation.

MacOS Intel
````
fyne package -os darwin -icon Icon.png
````
- Produces a MacOS application for Intel chipsets.

MacOS M1 / ARM64
````
fyne package -os darwin -arch arm64 -icon Icon.png
````
- Produces a MacOS application for Apple Silicon (M1/M2) chipsets.
  
⚠️ Cross-compilation may require platform-specific toolchains installed.
Example: On Windows, building for MacOS requires osxcross or building on a Mac.


## Configuration
Tunnel configurations are stored in tunnels.json. Each tunnel can be configured with:
- SSH Host / Port
- Username / Password or Key-based authentication
- 2FA enabled (optional)
- Forwarding type: Local, Remote, or Dynamic (SOCKS)
- Optional HTTP/HTTPS proxy

## Forwarding Types
Local Forwarding `(-L)`
````json
{
  "type": 0,
  "local_addr": "127.0.0.1:8080",
  "remote_addr": "remote.server.com:80"
}
````

Remote Forwarding `(-R)`
````json
{
  "type": 1,
  "local_addr": "127.0.0.1:80",
  "remote_addr": "remote.server.com:8080"
}
````

Dynamic Forwarding / SOCKS Proxy `(-D)`
````json
{
  "type": 2,
  "local_addr": "127.0.0.1:1080",
  "remote_addr": ""
}
````

SSH + HTTP/HTTPS Proxy Example
````json
"proxy": {
  "host": "proxy.company.com",
  "port": 8080,
  "username": "proxy_user",
  "password": "proxy_pass",
  "tls": true
}
````
SSH connections will first go through the proxy, then connect to the SSH server.

## Usage

1. Launch the GUI:
2. Add a new tunnel:
    - Enter SSH host, port, username.
    - Choose authentication method (password or key).
    - Select forwarding type (Local, Remote, Dynamic).
    - Optionally, enable proxy or 2FA.
3. Start/Stop tunnels from the GUI.

   Running tunnels show a green indicator; stopped tunnels show red.

4. Configurations are automatically saved to tunnels.json.


## Screenshots
<img width="1143" height="710" alt="image" src="https://github.com/user-attachments/assets/c29c9c6f-0af4-437a-a932-012ecf527243" />
<img width="1771" height="1182" alt="image" src="https://github.com/user-attachments/assets/64bfa666-5c7f-4c01-a940-7b2556b7d468" />
<img width="675" height="506" alt="image" src="https://github.com/user-attachments/assets/5493c159-58e3-4628-986f-c384799b3fa6" />


## License




MIT License © Grayson Lee

---
This version now includes:
1. **Compilation for Windows, MacOS Intel, MacOS M1**  
2. **Configuration examples for Local, Remote, Dynamic forwarding**  
3. **SSH + HTTP/HTTPS Proxy examples**  
4. **Usage instructions**  
5. **Full continuous flow suitable for GitHub**
---


