package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	logger  *zap.Logger
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
	zap.ReplaceGlobals(logger)
}

type Config struct {
	Path                   string
	SNI                    string
	Host                   string
	Password               string
	ALPN                   string
	CertificateFingerprint string
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

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
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

	uri := GenerateXHTTPTunnelURI(*host, *port, *path, *target, *psk, *sni, *remark, *pin, *insecure)
	fmt.Printf("=== 📱 xhttptunnel Sharing URI (encrypted stun://) ===\n\n%s\n", uri)
	PrintTerminalQR(uri)
}

// applyChunkSize clamps the user-supplied chunk size and recomputes the
// derived wire limits. 16KB is the smallest useful block, 900KB keeps a frame
// safely under a 1MB request-body ceiling once headers and padding are added.
func applyChunkSize(kb int) {
	if kb <= 0 {
		kb = defaultChunkSize / 1000
	}
	if kb < 16 {
		kb = 16
	}
	if kb > 900 {
		kb = 900
	}
	maxsendBufSize = kb * 1000
	maxframeSize = maxsendBufSize + framePaddingBudget
}

// applyServerOptions wires server-side tunables from the config file. Must run
// before ListenXHTTP, because the session registry reads these at startup.
func applyServerOptions(cfg *FileConfig) {
	if len(cfg.AllowedTargets) > 0 {
		allowedTargets = cfg.AllowedTargets
	}
	trustProxyHeaders = cfg.TrustProxyHeaders
	applyChunkSize(cfg.ChunkSizeKB)
}

// applyClientOptions wires client-side tunables from the config file.
func applyClientOptions(cfg *FileConfig) {
	if cfg.IdleTimeout > 0 {
		clientIdleTimeout = time.Duration(cfg.IdleTimeout) * time.Second
	}
	applyChunkSize(cfg.ChunkSizeKB)
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
		applyServerOptions(cfg)
		maxGlobalSessions = cfg.MaxSessions
		if maxGlobalSessions == 0 {
			maxGlobalSessions = 2000
		}
		logLevel := cfg.LogLevel
		if logLevel == "" {
			logLevel = "info"
		}
		initLogger(logLevel)
		defer logger.Sync()

		listen := cfg.Listen
		if listen == "" {
			listen = ":8443"
		}
		pathStr := cfg.Path
		if pathStr == "" {
			pathStr = "/stream"
		}
		target := cfg.Target
		if target == "" {
			target = cfg.DefaultTarget
		}
		if target == "" {
			target = "tcp://127.0.0.1:22"
		}
		psk := cfg.PSK
		if psk == "" {
			psk = "my-secret-token"
			logger.Warn("⚠️ 未配置 PSK，使用内置默认 token 'my-secret-token'，存在被未授权访问风险，请通过配置文件设置强 token！")
		}
		certFile := cfg.Cert
		keyFile := cfg.Key
		if cfg.SelfSign && (certFile == "" || keyFile == "") {
			certFile = "cert.pem"
			keyFile = "key.pem"
			cn := cfg.SelfSignCN
			if cn == "" {
				cn = "www.bing.com"
			}
			if err := generateSelfSignedCert(certFile, keyFile, cn); err != nil {
				logger.Fatal("Failed to generate self-signed certificate", zap.Error(err))
			}
		}
		runServer(ctx, listen, pathStr, target, psk, certFile, keyFile, cfg.Dump, cfg.Fallback)

	case "client":
		cfg := resolveConfig(os.Args[2:])
		applyClientOptions(cfg)
		maxClientSessions = cfg.MaxConns
		if maxClientSessions == 0 {
			maxClientSessions = 2000
		}
		logLevel := cfg.LogLevel
		if logLevel == "" {
			logLevel = "info"
		}
		initLogger(logLevel)
		defer logger.Sync()

		listen := cfg.Listen
		if listen == "" {
			listen = "tcp://127.0.0.1:1080"
		}
		serverURL := cfg.ServerURL
		if serverURL == "" {
			serverURL = "https://127.0.0.1:8443/stream"
		}
		forward := cfg.Target
		if forward == "" {
			forward = cfg.Forward
		}
		if forward == "" {
			forward = "127.0.0.1:22"
		}
		psk := cfg.PSK
		if psk == "" {
			psk = "my-secret-token"
			logger.Warn("⚠️ 未配置 PSK，使用内置默认 token 'my-secret-token'，存在被未授权访问风险，请通过配置文件设置强 token！")
		}
		alpn := cfg.ALPN
		if alpn == "" {
			alpn = "auto"
		}
		runClient(ctx, listen, serverURL, forward, psk, cfg.SNI, cfg.Host, alpn, cfg.Dump, cfg.Fingerprint)

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

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	initLogger(logLevel)
	defer logger.Sync()

	if strings.ToLower(cfg.Mode) == "client" {
		applyClientOptions(cfg)
		if cfg.MaxConns > 0 {
			maxClientSessions = cfg.MaxConns
		}
		listen := cfg.Listen
		if listen == "" {
			listen = "tcp://127.0.0.1:1080"
		}
		alpn := cfg.ALPN
		if alpn == "" {
			alpn = "auto"
		}
		serverURL := cfg.ServerURL
		if serverURL == "" {
			serverURL = "https://127.0.0.1:8443/stream"
		}
		forward := cfg.Target
		if forward == "" {
			forward = cfg.Forward
		}
		if forward == "" {
			forward = "127.0.0.1:22"
		}
		if cfg.PSK == "" {
			logger.Warn("⚠️ 配置文件未设置 PSK，客户端将以无鉴权方式连接。")
		}
		runClient(ctx, listen, serverURL, forward, cfg.PSK, cfg.SNI, cfg.Host, alpn, cfg.Dump, cfg.Fingerprint)
	} else {
		applyServerOptions(cfg)
		if cfg.MaxSessions > 0 {
			maxGlobalSessions = cfg.MaxSessions
		}
		listen := cfg.Listen
		if listen == "" {
			listen = ":8443"
		}
		pathStr := cfg.Path
		if pathStr == "" {
			pathStr = "/stream"
		}
		target := cfg.Target
		if target == "" {
			target = cfg.DefaultTarget
		}
		if target == "" {
			target = "tcp://127.0.0.1:22"
		}
		certFile := cfg.Cert
		keyFile := cfg.Key
		if cfg.SelfSign && (certFile == "" || keyFile == "") {
			certFile = "cert.pem"
			keyFile = "key.pem"
			cn := cfg.SelfSignCN
			if cn == "" {
				cn = "www.bing.com"
			}
			if err := generateSelfSignedCert(certFile, keyFile, cn); err != nil {
				logger.Fatal("Failed to generate self-signed certificate", zap.Error(err))
			}
		}
		if cfg.PSK == "" {
			logger.Warn("⚠️ 配置文件未设置 PSK，服务器将以开放模式运行（无鉴权），请勿在公网暴露。")
		}
		runServer(ctx, listen, pathStr, target, cfg.PSK, certFile, keyFile, cfg.Dump, cfg.Fallback)
	}
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
