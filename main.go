package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/NNdroid/xhttptunnel/tunnel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// version may be injected at link time with
	//   -ldflags "-X main.version=<semver>"
	// It intentionally shadows Version (kept for backward compatibility) so a
	// build script can stamp the binary without editing source.
	version string

	// Version is the human-facing version string. Prefer versionString() so a
	// linker-injected version wins over the source default.
	Version = "1.1.0"
	// logger is the CLI's own sink for startup warnings and errors; all
	// protocol-level logging flows through the tunnel package logger, which
	// initLogger keeps in sync with this one.
	logger = zap.NewNop()
)

func versionString() string {
	if version != "" {
		return version
	}
	return Version
}

func isPlaceholderPSK(psk string) bool {
	switch strings.TrimSpace(psk) {
	case "my-secret-token", "change-me-before-use", "replace-with-a-random-secret":
		return true
	default:
		return false
	}
}

func initLogger(levelStr string) {
	config := zap.NewProductionConfig()
	config.Encoding = "console"
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(levelStr))); err != nil {
		level = zap.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(level)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ = config.Build()
	tunnel.SetLogger(logger)
}

type FileConfig struct {
	Mode          string `json:"mode"`           // "server" or "client"
	Listen        string `json:"listen"`         // Server or client listen address
	Path          string `json:"path"`           // Custom XHTTP path
	ServerURL     string `json:"server"`         // Client upstream server URL
	Target        string `json:"target"`         // Forwarding target (server default or client target)
	DefaultTarget string `json:"default_target"` // Server default target (alias)
	Forward       string `json:"forward"`        // Client forward target (alias)
	PSK           string `json:"psk"`            // Pre-shared key / token
	Cert          string `json:"cert"`           // TLS certificate file
	Key           string `json:"key"`            // TLS private key file
	SelfSign      bool   `json:"selfsign"`       // Auto self-signed cert
	SelfSignCN    string `json:"selfsign_cn"`    // Common name for self-signed cert
	Fallback      string `json:"fallback"`       // Fallback URL for unauthorized requests
	SNI           string `json:"sni"`            // TLS SNI disguise
	Host          string `json:"host"`           // HTTP Host header disguise
	ALPN          string `json:"alpn"`           // ALPN selection (h3, h2, h1, auto)
	Fingerprint   string `json:"fingerprint"`    // Expected certificate SHA256 fingerprint
	LogLevel      string `json:"log_level"`      // debug, info, warn, error
	Dump          bool   `json:"dump"`           // Dump hex traffic
	MaxSessions   int    `json:"max_sessions"`   // Server max concurrent sessions
	// MaxSessionsPerIP bounds concurrent sessions from a single client address,
	// limiting one PSK holder's blast radius. 0 (default) disables.
	MaxSessionsPerIP int `json:"max_sessions_per_ip"`
	// HealthPath, when set (e.g. "/healthz"), exposes an unauthenticated JSON
	// stats endpoint on the tunnel listener. Empty disables it.
	HealthPath string `json:"health_path"`
	// MinProtoVersion rejects (HTTP 426) clients advertising an older
	// X-XHTTP-Proto than this, to force a fleet off a retired wire format. 0
	// (default) accepts all clients including header-less legacy ones.
	MinProtoVersion int `json:"min_proto_version"`
	MaxConns        int `json:"max_conns"` // Client max concurrent connections
	// ChunkSizeKB caps the upstream payload carried by one poll request. The
	// default (256) leaves headroom under the 1MB body limit that nginx and
	// many CDN/WAF tiers enforce. Must be raised on BOTH ends together.
	ChunkSizeKB int `json:"chunk_size_kb"`
	// IdleTimeout (client) drops a local connection after this many seconds
	// without traffic. Default 900. Idle SSH sessions need keepalives below it.
	IdleTimeout int `json:"idle_timeout"`
	// AllowedTargets (server) restricts which targets clients may request.
	// Entries may be "host:port", ":port" or "host:". Empty = allow all.
	AllowedTargets []string `json:"allowed_targets"`
	// StreamMode (client) selects the downlink transport: "" / "auto" runs
	// the automatic negotiation, "poll" forces the legacy long-poll mode,
	// "stream" forces the streaming downlink. Invalid values fail startup.
	StreamMode string `json:"stream_mode"`
	// TrustProxyHeaders (server) makes the client address logged via
	// CF-Connecting-IP / X-Forwarded-For / X-Real-IP headers instead of the
	// socket peer. Those headers are spoofable, so keep this OFF unless the
	// server is reachable only through a trusted CDN/proxy that strips them.
	TrustProxyHeaders bool `json:"trust_proxy_headers"`
	// Brutal configures TCP Brutal (Linux only) on the tunnel's TCP sockets.
	// Nested object; see the "brutal" block in the sample configs. Disabled by
	// default, so a config without this key behaves exactly as before.
	Brutal tunnel.BrutalConfig `json:"brutal"`
}

func (fc *FileConfig) UnmarshalJSON(data []byte) error {
	type Alias FileConfig
	aux := struct {
		*Alias
		RawToken     string `json:"token"`
		RawAuthToken string `json:"auth_token"`
	}{
		Alias: (*Alias)(fc),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if fc.PSK == "" {
		if aux.RawToken != "" {
			fc.PSK = aux.RawToken
		} else if aux.RawAuthToken != "" {
			fc.PSK = aux.RawAuthToken
		}
	}

	if fc.Target != "" {
		if fc.DefaultTarget == "" {
			fc.DefaultTarget = fc.Target
		}
		if fc.Forward == "" {
			fc.Forward = fc.Target
		}
	} else {
		if fc.DefaultTarget != "" {
			fc.Target = fc.DefaultTarget
		} else if fc.Forward != "" {
			fc.Target = fc.Forward
		}
	}

	return nil
}

func applyEnvOverrides(cfg *FileConfig) {
	getEnv := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	if v := getEnv("XHTTPTUNNEL_MODE", "MODE"); v != "" {
		cfg.Mode = v
	}
	if v := getEnv("XHTTPTUNNEL_LISTEN", "LISTEN", "PORT"); v != "" {
		if !strings.Contains(v, ":") && len(v) < 6 {
			cfg.Listen = ":" + v
		} else {
			cfg.Listen = v
		}
	}
	if v := getEnv("XHTTPTUNNEL_SERVER", "SERVER"); v != "" {
		cfg.ServerURL = v
	}
	if v := getEnv("XHTTPTUNNEL_TARGET", "TARGET"); v != "" {
		cfg.Target = v
	}
	if v := getEnv("XHTTPTUNNEL_PATH", "TUNNEL_PATH", "PROXY_PATH"); v != "" {
		cfg.Path = v
	}
	if v := getEnv("XHTTPTUNNEL_PSK", "XHTTPTUNNEL_TOKEN", "PSK", "TOKEN"); v != "" {
		cfg.PSK = v
	}
	if v := getEnv("XHTTPTUNNEL_FALLBACK", "FALLBACK"); v != "" {
		cfg.Fallback = v
	}
	if v := getEnv("XHTTPTUNNEL_LOG_LEVEL", "LOG_LEVEL", "LOGLEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

func runGenURI(args []string) {
	fs := flag.NewFlagSet("gen-uri", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	host := fs.String("host", "", "Server public IP or domain")
	port := fs.String("port", "", "Server listen port")
	path := fs.String("path", "", "Proxy path")
	target := fs.String("target", "", "Forward target")
	psk := fs.String("psk", "", "PSK token")
	sni := fs.String("sni", "", "SNI disguise")
	fingerprint := fs.String("fingerprint", "", "Server certificate SHA-256 pin")
	remark := fs.String("name", "", "Node remark name")
	insecure := fs.Bool("insecure", true, "Skip TLS verify")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// The config file takes precedence over built-in defaults, but command-line
	// flags can override any field of the config.
	var certFile string
	var selfSigned bool
	if *cfgPath != "" {
		if fileCfg, err := loadConfigFile(*cfgPath); err == nil {
			// Prefer deriving the public host/port from the client config's server URL
			if *host == "" && fileCfg.ServerURL != "" {
				if u, err := url.Parse(fileCfg.ServerURL); err == nil && u.Host != "" {
					*host = u.Hostname()
					if u.Port() != "" {
						*port = u.Port()
					}
				}
			}
			if *port == "" && fileCfg.Listen != "" {
				if _, p, err := net.SplitHostPort(fileCfg.Listen); err == nil {
					*port = p
				}
			}
			if *path == "" && fileCfg.Path != "" {
				*path = fileCfg.Path
			}
			if *target == "" && fileCfg.Target != "" {
				*target = fileCfg.Target
			}
			if *psk == "" && fileCfg.PSK != "" {
				*psk = fileCfg.PSK
			}
			if *sni == "" && fileCfg.SNI != "" {
				*sni = fileCfg.SNI
			}
			// A server config keeps its disguise domain as selfsign_cn rather
			// than sni, so without this a share URI generated from
			// config.server.json would carry no SNI at all and the client's TLS
			// handshake to the origin would fail right after the scan. The one
			// value feeds both the SNI and the HTTP Host disguise. The check is
			// not gated on selfsign: a static cert paired with a selfsign_cn
			// still wants that domain as its disguise.
			if *sni == "" && fileCfg.SelfSignCN != "" {
				*sni = fileCfg.SelfSignCN
			}
			if *fingerprint == "" && fileCfg.Fingerprint != "" {
				*fingerprint = fileCfg.Fingerprint
			}
			certFile = fileCfg.Cert
			selfSigned = fileCfg.SelfSign
		}
	}

	// Built-in defaults as a last resort
	if *host == "" {
		*host = "your-server-ip"
	}
	if *port == "" {
		*port = "8443"
	}
	if *path == "" {
		*path = "/stream"
	}
	if *target == "" {
		*target = "127.0.0.1:22"
	}
	if *remark == "" {
		*remark = "XHTTPTunnel Node"
	}

	// A pin only helps for a certificate that stays put. A static cert file can
	// be hashed right here. gen-uri never runs applyServerDefaults, so a
	// selfsign-only config gives it nothing to hash: the pair the server writes
	// beside the config file is invisible from here.
	if *fingerprint == "" && certFile != "" {
		if fp, err := tunnel.CertFingerprint(certFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not derive the certificate fingerprint from %s (%v); the URI carries no pin\n\n", certFile, err)
		} else {
			*fingerprint = fp
		}
	} else if selfSigned && *fingerprint == "" {
		fmt.Fprintf(os.Stderr, "Warning: selfsign is on but cert is empty, so the URI carries no pin and gen-uri has nothing to hash. Point cert at the pair the server writes beside the config file, or pass -fingerprint.\n\n")
	}

	uri := tunnel.GenerateXHTTPTunnelURI(*host, *port, *path, *target, *psk, *sni, *fingerprint, *remark, *pin, *insecure)
	fmt.Printf("=== 📱 xhttptunnel Sharing URI (encrypted stun://) ===\n\n%s\n", uri)
	tunnel.PrintTerminalQR(uri)
}

// applyClientDefaults fills the structural defaults shared by the `client`
// subcommand and the -c config.json bootstrap. The built-in default PSK is
// deliberately NOT applied here: config-file bootstrapping runs in open mode
// with a warning instead of silently using a well-known token.
func applyClientDefaults(cfg *FileConfig) {
	if cfg.Listen == "" {
		cfg.Listen = "tcp://127.0.0.1:1080"
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "https://127.0.0.1:8443/stream"
	}
	if cfg.Target == "" {
		cfg.Target = cfg.Forward
	}
	if cfg.Target == "" {
		cfg.Target = "127.0.0.1:22"
	}
	if cfg.ALPN == "" {
		cfg.ALPN = "auto"
	}
}

// applyServerDefaults fills the structural defaults shared by the `server`
// subcommand and the -c config.json bootstrap, including self-signed
// certificate generation. configPath is the file those defaults came from,
// or "" for a flag-only run; it anchors where a generated certificate pair
// is written. PSK handling is left to the caller (see applyClientDefaults
// for the rationale).
func applyServerDefaults(cfg *FileConfig, configPath string) error {
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.Path == "" {
		cfg.Path = "/stream"
	}
	if cfg.Target == "" {
		cfg.Target = cfg.DefaultTarget
	}
	if cfg.Target == "" {
		cfg.Target = "tcp://127.0.0.1:22"
	}
	if cfg.SelfSign {
		cn := cfg.SelfSignCN
		if cn == "" {
			cn = "www.bing.com"
		}

		// The pair lands beside the config file, never in the process working
		// directory: systemd starts the binary from wherever it pleases, so a
		// CWD-relative name would scatter a private key and could not match
		// the path a deployed config advertises. An explicitly configured
		// cert/key path is honoured as the generation target, so selfsign and
		// a fixed certificate location can be combined instead of excluded.
		certPath, keyPath := cfg.Cert, cfg.Key
		if certPath == "" || keyPath == "" {
			dir := configDir(configPath)
			if certPath == "" {
				certPath = filepath.Join(dir, "cert.pem")
			}
			if keyPath == "" {
				keyPath = filepath.Join(dir, "key.pem")
			}
		}

		missing := func(p string) bool { _, err := os.Stat(p); return err != nil }
		if missing(certPath) || missing(keyPath) {
			if !missing(certPath) || !missing(keyPath) {
				// Exactly one half exists. Generating would overwrite it, so
				// refuse instead of destroying a certificate the operator has.
				return fmt.Errorf("selfsign needs a complete certificate pair: %s and %s must both be present or both absent", certPath, keyPath)
			}
			if err := tunnel.GenerateSelfSignedCert(certPath, keyPath, cn); err != nil {
				return fmt.Errorf("generate self-signed certificate: %w", err)
			}
		}
		// A complete pair already exists, so it is reused as-is. Regenerating
		// on every boot would change the certificate and break a client that
		// pins it by fingerprint.
		cfg.Cert, cfg.Key = certPath, keyPath
	}
	return nil
}

// configDir resolves the directory a self-signed pair is written into. A flag
// driven run has no config file, so it falls back to the working directory —
// the only directory such a run has.
func configDir(path string) string {
	if path == "" {
		return "."
	}
	if d := filepath.Dir(path); d != "" {
		return d
	}
	return "."
}

func loadConfigFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg FileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func main() {
	// Stamp the tunnel User-Agent with the CLI version.
	tunnel.Version = versionString()

	if len(os.Args) > 1 && (os.Args[1] == "-c" || os.Args[1] == "--config" || strings.HasPrefix(os.Args[1], "-c=") || strings.HasPrefix(os.Args[1], "--config=")) {
		confPath := "config.json"
		if strings.Contains(os.Args[1], "=") {
			confPath = strings.SplitN(os.Args[1], "=", 2)[1]
		} else if len(os.Args) > 2 {
			confPath = os.Args[2]
		}
		runFromConfig(confPath)
		return
	}

	if len(os.Args) < 2 {
		if _, err := os.Stat("config.json"); err == nil {
			runFromConfig("config.json")
			return
		}
		printUsage()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch os.Args[1] {
	case "gen-uri":
		runGenURI(os.Args[2:])
	case "gen-nginx":
		runGenNginx(os.Args[2:])
	case "gen-systemd":
		runGenSystemd(os.Args[2:])
	// gen-conf is the short spelling operators reach for; keep both so an
	// already-learned muscle memory still works.
	case "gen-config", "gen-conf", "gen-cfg":
		runGenConfig(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("xhttptunnel version %s\n", versionString())
	case "help", "-h", "--help":
		printUsage()
	case "server":
		cfg, cfgPath := resolveConfig(os.Args[2:])
		initLogger(cfg.LogLevel)
		defer logger.Sync()
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		if err := applyServerDefaults(cfg, cfgPath); err != nil {
			logger.Fatal("❌ server failed to start", zap.Error(err))
		}
		if cfg.PSK == "" {
			logger.Fatal("❌ PSK not configured; the server subcommand will not use a public default password. Set a strong random PSK explicitly, or opt into open mode via the config file")
		}
		if isPlaceholderPSK(cfg.PSK) {
			logger.Fatal("❌ refusing an example PSK; configure a deployment-specific strong random password")
		}
		startServer(ctx, cfg)

	case "client":
		cfg, _ := resolveConfig(os.Args[2:])
		initLogger(cfg.LogLevel)
		defer logger.Sync()
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		applyClientDefaults(cfg)
		if cfg.PSK == "" {
			logger.Fatal("❌ PSK not configured; the client subcommand will not use a public default password. Set the server's PSK explicitly, or opt into unauthenticated mode via the config file")
		}
		if isPlaceholderPSK(cfg.PSK) {
			logger.Fatal("❌ refusing an example PSK; set the password the server actually uses")
		}
		startClient(ctx, cfg)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// resolveConfig loads the -c/--config file if specified and returns the merged
// FileConfig. The per-parameter command-line flags have been removed; the
// configuration file is now the single source of truth, and built-in defaults
// are applied per subcommand so the program still runs with zero configuration.
func resolveConfig(args []string) (*FileConfig, string) {
	fs := flag.NewFlagSet("xhttptunnel", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	confPath := fs.String("config", "", "Path to configuration file")
	_ = fs.Parse(args)

	cp := *cfgPath
	if cp == "" {
		cp = *confPath
	}
	cfg := &FileConfig{}
	if cp != "" {
		fileCfg, err := loadConfigFile(cp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", cp, err)
			os.Exit(1)
		}
		cfg = fileCfg
	}
	applyEnvOverrides(cfg)
	return cfg, cp
}

// startClient builds a tunnel.Client from the resolved configuration and runs
// the blocking local forwarder. It exits the process on startup failure.
func startClient(ctx context.Context, cfg *FileConfig) {
	c, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerURL:   cfg.ServerURL,
		PSK:         cfg.PSK,
		SNI:         cfg.SNI,
		Host:        cfg.Host,
		ALPN:        cfg.ALPN,
		Fingerprint: cfg.Fingerprint,
		Target:      cfg.Target,
		MaxConns:    cfg.MaxConns,
		IdleTimeout: time.Duration(cfg.IdleTimeout) * time.Second,
		StreamMode:  cfg.StreamMode,
		Dump:        cfg.Dump,
		Brutal:      cfg.Brutal,
	})
	if err != nil {
		logger.Fatal("❌ client failed to start", zap.Error(err))
	}
	if err := c.ListenAndServe(ctx, cfg.Listen); err != nil && ctx.Err() == nil {
		logger.Fatal("❌ client exited", zap.Error(err))
	}
}

// startServer builds a tunnel.Server from the resolved configuration and runs
// the blocking accept/bridge loop. It exits the process on startup failure.
func startServer(ctx context.Context, cfg *FileConfig) {
	s, err := tunnel.NewServer(tunnel.ServerConfig{
		Listen:            cfg.Listen,
		Path:              cfg.Path,
		PSK:               cfg.PSK,
		CertFile:          cfg.Cert,
		KeyFile:           cfg.Key,
		Fallback:          cfg.Fallback,
		DefaultTarget:     cfg.Target,
		AllowedTargets:    cfg.AllowedTargets,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		MaxSessions:       cfg.MaxSessions,
		MaxSessionsPerIP:  cfg.MaxSessionsPerIP,
		HealthPath:        cfg.HealthPath,
		MinProtoVersion:   cfg.MinProtoVersion,
		Dump:              cfg.Dump,
		Brutal:            cfg.Brutal,
	})
	if err != nil {
		logger.Fatal("❌ server failed to start", zap.Error(err))
	}
	if err := s.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		logger.Fatal("❌ server exited", zap.Error(err))
	}
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	initLogger(cfg.LogLevel)
	defer logger.Sync()

	if strings.ToLower(cfg.Mode) == "client" {
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		applyClientDefaults(cfg)
		if isPlaceholderPSK(cfg.PSK) {
			logger.Fatal("❌ config file contains a public example PSK; set the password the server actually uses")
		}
		if cfg.PSK == "" {
			logger.Warn("⚠️ no PSK set in the config file; the client will connect unauthenticated.")
		}
		startClient(ctx, cfg)
	} else {
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		if err := applyServerDefaults(cfg, path); err != nil {
			logger.Fatal("❌ server failed to start", zap.Error(err))
		}
		if isPlaceholderPSK(cfg.PSK) {
			logger.Fatal("❌ config file contains a public example PSK; replace it with a deployment-specific strong random password first")
		}
		if cfg.PSK == "" {
			logger.Warn("⚠️ no PSK set in the config file; the server runs in open mode (unauthenticated). Do not expose it publicly.")
		}
		startServer(ctx, cfg)
	}
}

// runClient mirrors the historical CLI entry point: a blocking local
// forwarder with per-call parameters. The subcommands construct the tunnel
// package types directly; this shim remains for tests and quick embedding.
// It returns the startup or serve error instead of exiting, so callers can
// decide how loudly to fail.
func runClient(ctx context.Context, listenStr, serverURLStr, forwardTarget, psk, customSNI, customHost, alpn string, dump bool, fingerprint string) error {
	c, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerURL:   serverURLStr,
		PSK:         psk,
		SNI:         customSNI,
		Host:        customHost,
		ALPN:        alpn,
		Fingerprint: fingerprint,
		Target:      forwardTarget,
		Dump:        dump,
	})
	if err != nil {
		return err
	}
	return c.ListenAndServe(ctx, listenStr)
}

// runServer mirrors the historical CLI entry point: a blocking server with
// per-call parameters. See startServer for the config-file driven path.
func runServer(ctx context.Context, listenAddr, path, defaultTargetStr, psk, certFile, keyFile string, dump bool, fallback string) error {
	s, err := tunnel.NewServer(tunnel.ServerConfig{
		Listen:        listenAddr,
		Path:          path,
		PSK:           psk,
		CertFile:      certFile,
		KeyFile:       keyFile,
		DefaultTarget: defaultTargetStr,
		Dump:          dump,
		Fallback:      fallback,
	})
	if err != nil {
		return err
	}
	return s.ListenAndServe(ctx)
}

func printUsage() {
	fmt.Println("Usage: xhttptunnel <command> [args] or xhttptunnel -c config.json")
	fmt.Println("\nCommands:")
	fmt.Println("  server       Start tunnel server")
	fmt.Println("  client       Start tunnel client")
	fmt.Println("  gen-uri      Generate Stun client sharing URI link & QR Code")
	fmt.Println("  gen-config   Generate a server/client configuration file (alias gen-conf)")
	fmt.Println("  gen-nginx    Generate Nginx reverse proxy configuration")
	fmt.Println("  gen-systemd  Generate a hardened Linux systemd service configuration")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show help message")
}
