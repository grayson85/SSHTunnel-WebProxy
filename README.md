# SSH Tunnels + Web Proxy GUI @GraysonLee

A simple GUI application in **Go** using **Fyne** to manage SSH tunnels, dynamic port forwarding (SOCKS), and optional HTTP/HTTPS proxy support. Supports password/key-based authentication, including 2FA.

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
