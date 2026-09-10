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
	MaxConns      int    `json:"max_conns"`      // Client max concurrent connections
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
	remark := fs.String("name", "", "Node remark name")
	insecure := fs.Bool("insecure", true, "Skip TLS verify")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// The config file takes precedence over built-in defaults, but command-line
	// flags can override any field of the config.
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

	uri := tunnel.GenerateXHTTPTunnelURI(*host, *port, *path, *target, *psk, *sni, *remark, *pin, *insecure)
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
// certificate generation. PSK handling is left to the caller (see
// applyClientDefaults for the rationale).
func applyServerDefaults(cfg *FileConfig) error {
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
	if cfg.SelfSign && (cfg.Cert == "" || cfg.Key == "") {
		cn := cfg.SelfSignCN
		if cn == "" {
			cn = "www.bing.com"
		}
		if err := tunnel.GenerateSelfSignedCert("cert.pem", "key.pem", cn); err != nil {
			return fmt.Errorf("generate self-signed certificate: %w", err)
		}
		cfg.Cert = "cert.pem"
		cfg.Key = "key.pem"
	}
	return nil
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
	case "version", "-v", "--version":
		fmt.Printf("xhttptunnel version %s\n", versionString())
	case "help", "-h", "--help":
		printUsage()
	case "server":
		cfg := resolveConfig(os.Args[2:])
		initLogger(cfg.LogLevel)
		defer logger.Sync()
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		if err := applyServerDefaults(cfg); err != nil {
			logger.Fatal("❌ 服务端启动失败", zap.Error(err))
		}
		if cfg.PSK == "" {
			cfg.PSK = "my-secret-token"
			logger.Warn("⚠️ 未配置 PSK，使用内置默认 token 'my-secret-token'，存在被未授权访问风险，请通过配置文件设置强 token！")
		}
		startServer(ctx, cfg)

	case "client":
		cfg := resolveConfig(os.Args[2:])
		initLogger(cfg.LogLevel)
		defer logger.Sync()
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		applyClientDefaults(cfg)
		if cfg.PSK == "" {
			cfg.PSK = "my-secret-token"
			logger.Warn("⚠️ 未配置 PSK，使用内置默认 token 'my-secret-token'，存在被未授权访问风险，请通过配置文件设置强 token！")
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
func resolveConfig(args []string) *FileConfig {
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
	return cfg
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
	})
	if err != nil {
		logger.Fatal("❌ 客户端启动失败", zap.Error(err))
	}
	if err := c.ListenAndServe(ctx, cfg.Listen); err != nil && ctx.Err() == nil {
		logger.Fatal("❌ 客户端退出", zap.Error(err))
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
		Dump:              cfg.Dump,
	})
	if err != nil {
		logger.Fatal("❌ 服务端启动失败", zap.Error(err))
	}
	if err := s.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		logger.Fatal("❌ 服务端退出", zap.Error(err))
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
		if cfg.PSK == "" {
			logger.Warn("⚠️ 配置文件未设置 PSK，客户端将以无鉴权方式连接。")
		}
		startClient(ctx, cfg)
	} else {
		tunnel.SetChunkSizeKB(cfg.ChunkSizeKB)
		if err := applyServerDefaults(cfg); err != nil {
			logger.Fatal("❌ 服务端启动失败", zap.Error(err))
		}
		if cfg.PSK == "" {
			logger.Warn("⚠️ 配置文件未设置 PSK，服务器将以开放模式运行（无鉴权），请勿在公网暴露。")
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
	fmt.Println("  gen-nginx    Generate Nginx reverse proxy configuration snippet")
	fmt.Println("  gen-systemd  Generate Linux systemd service configuration")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show help message")
}
