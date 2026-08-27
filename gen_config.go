package main

import (
	"flag"
	"fmt"
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
    proxy_buffering off;
    proxy_pass http://%s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass_request_headers on;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
`, *domain, *path, *backend)
}

func runGenSystemd(args []string) {
	cmd := flag.NewFlagSet("gen-systemd", flag.ExitOnError)
	binPath := cmd.String("bin", "/usr/local/bin/xhttptunnel", "xhttptunnel binary path")
	listen := cmd.String("listen", "127.0.0.1:8443", "Server listen address")
	path := cmd.String("path", "/stream", "Proxy path")
	psk := cmd.String("psk", "your-secret-token", "Pre-shared PSK / Token")
	defaultTarget := cmd.String("default-target", "tcp://127.0.0.1:22", "Default target forwarding address")
	_ = cmd.Parse(args)

	// The `server` subcommand only accepts `-c/--config` (per-parameter flags were
	// removed), so the unit always launches from a config file.
	execLine := fmt.Sprintf("%s -c /etc/xhttptunnel/config.json", *binPath)

	configSample := fmt.Sprintf(`{
  "mode": "server",
  "listen": %q,
  "path": %q,
  "default_target": %q,
  "psk": %q,
  "log_level": "info"
}`, *listen, *path, *defaultTarget, *psk)

	fmt.Printf(`[Unit]
Description=xhttptunnel High-Performance Split-HTTP Tunnel Server
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
`, execLine)

	fmt.Println("# Place the following as /etc/xhttptunnel/config.json :")
	fmt.Println(configSample)
}
