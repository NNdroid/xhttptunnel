package main

import (
	"flag"
	"fmt"
	"strings"
)

func runGenNginx(args []string) {
	cmd := flag.NewFlagSet("gen-nginx", flag.ExitOnError)
	domain := cmd.String("domain", "yourdomain.com", "Your domain name")
	path := cmd.String("path", "/stream", "XHTTPTunnel proxy path")
	backend := cmd.String("backend", "127.0.0.1:8443", "XHTTPTunnel backend local address")
	_ = cmd.Parse(args)

	fmt.Printf(`
# ====================================================================
# Nginx XHTTP (Split-HTTP) Reverse Proxy Configuration (%s)
# (Paste inside your server { ... } block)
# ====================================================================

location %s {
    # Tunnel responses stream continuously; never buffer them at the edge.
    proxy_buffering off;
    # nginx buffers the whole request body by default, which destroys the
    # streaming upstream path. Streaming mode is required here.
    proxy_request_buffering off;
    # Poll bodies are up to chunk_size_kb (default 256KB); do not impose the
    # 1MB default limit on them.
    client_max_body_size 0;

    proxy_pass http://%s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # Proxy-Authorization is hop-by-hop and some intermediaries remove it.
    # Preserve the tunnel's end-to-end credential header explicitly.
    proxy_set_header X-Auth-Token $http_x_auth_token;
    proxy_pass_request_headers on;
    # Long timeouts so parked poll requests are not cut off.
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
`, *domain, *path, *backend)
}

func runGenSystemd(args []string) {
	cmd := flag.NewFlagSet("gen-systemd", flag.ExitOnError)
	binPath := cmd.String("bin", "/usr/local/bin/xhttptunnel", "xhttptunnel binary path")
	mode := cmd.String("mode", "server", "Service mode: server or client")
	listen := cmd.String("listen", "127.0.0.1:8443", "Server listen address (server mode)")
	path := cmd.String("path", "/stream", "Proxy path")
	psk := cmd.String("psk", "your-secret-token", "Pre-shared PSK / Token")
	defaultTarget := cmd.String("default-target", "tcp://127.0.0.1:22", "Default target forwarding address (server mode)")
	_ = cmd.Parse(args)

	// The `server`/`client` subcommands only accept `-c/--config` (per-parameter
	// flags were removed), so the unit always launches from a config file.
	// Name the file per-mode (config.<mode>.json) to match install.sh's
	// get_config_file convention, so a unit produced here points at the same
	// file install.sh writes — `gen-systemd` and `install.sh` stay consistent.
	configFile := fmt.Sprintf("/etc/xhttptunnel/config.%s.json", *mode)
	execLine := fmt.Sprintf("%s -c %s", *binPath, configFile)

	// Generate a starter config sample matching the selected mode.
	var configSample string
	if strings.EqualFold(*mode, "client") {
		configSample = fmt.Sprintf(`{
  "mode": "client",
  "listen": "tcp://127.0.0.1:1080",
  "server": "https://example.com:8443%s",
  "target": %q,
  "psk": %q,
  "sni": "www.bing.com",
  "host": "www.bing.com",
  "alpn": "auto",
  "max_conns": 512,
  "log_level": "info"
}`, *path, *defaultTarget, *psk)
	} else {
		configSample = fmt.Sprintf(`{
  "mode": "server",
  "listen": %q,
  "path": %q,
  "default_target": %q,
  "psk": %q,
  "log_level": "info"
}`, *listen, *path, *defaultTarget, *psk)
	}

	desc := "Server"
	if strings.EqualFold(*mode, "client") {
		desc = "Client"
	}

	fmt.Printf(`[Unit]
Description=xhttptunnel High-Performance Split-HTTP Tunnel %s
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xhttptunnel
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, desc, execLine)

	fmt.Printf("# Place the following as %s :\n", configFile)
	fmt.Println(configSample)
}
