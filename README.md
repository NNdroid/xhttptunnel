# xhttptunnel

xhttptunnel is a high-performance, anti-censorship HTTP/2 & HTTP/3 tunnel tool designed for complex network environments. It effectively obfuscates traffic signatures and bypasses Deep Packet Inspection (DPI) through dynamic padding, sliding windows, and long-polling mechanisms.

## ✨ Core Features

* **Multi-Protocol Transport Engine**: Supports plain text H2C, TLS (HTTP/2), and QUIC-based HTTP/3 transport.
* **Full-Stack Traffic Proxying**: Native support for efficient multiplexing and forwarding of both TCP and UDP traffic, with built-in automatic recycling of idle UDP sessions.
* **Deep Traffic Obfuscation (DPI Bypass)**: Built-in frame-level dynamic Padding and 0xFFFF signaling armor completely break traffic fingerprinting.
* **Connection State Optimization**: Uses a custom high-performance reliable transport buffer (Seq/Ack mechanism), combined with intelligent server-side long-polling and heartbeat back-off algorithms, achieving `0` latency with extremely low CPU and network overhead.
* **Minimalist Deployment**: Comes with a one-click installation script, supporting automated configuration of systemd services and self-signed certificates.

## 🚀 Quick Installation (Server)

We provide a one-click installation script that automatically installs dependencies, pulls the latest release, and configures the background daemon.

### Option 1: Fully Automatic Installation (Recommended)
Automatically generates a random PSK key and a random 2-level Path route to enhance security:
```bash
bash -c "$(curl -L [https://raw.githubusercontent.com/NNdroid/xhttptunnel/refs/heads/main/scripts/install.sh](https://raw.githubusercontent.com/NNdroid/xhttptunnel/refs/heads/main/scripts/install.sh))" @ install
```

### Option 2: Custom Parameter Installation
Manually specify your desired PSK key and proxy path:
```bash
bash -c "$(curl -L [https://raw.githubusercontent.com/NNdroid/xhttptunnel/refs/heads/main/scripts/install.sh](https://raw.githubusercontent.com/NNdroid/xhttptunnel/refs/heads/main/scripts/install.sh))" @ install --psk your_psk --path /your/path
```

> **Note:** The script also supports `uninstall` (complete removal) and `update` (updates the core program while retaining configuration) commands.

## 📱 Client Support

* [**Stun**](https://github.com/NNdroid/Stun) - Official Android client implementation, supporting VpnService-based and underlying Root-level global transparent proxying.

---
*© NNdroid 2026*