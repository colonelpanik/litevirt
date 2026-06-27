package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

// ConfigDir returns the litevirt configuration directory.
func ConfigDir() string {
	if d := os.Getenv("LV_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "litevirt")
}

// PKIDir returns the PKI directory inside the config dir.
func PKIDir() string {
	return filepath.Join(ConfigDir(), "pki")
}

// ClusterConfig holds the current cluster connection info.
type ClusterConfig struct {
	DefaultHost string // host or host:port for direct gRPC (empty in local mode)
	GRPCPort    int
	PKIDir      string
	Local       bool // true when running on a litevirtd node
}

// localDaemonConfig is a minimal subset of the daemon config file.
type localDaemonConfig struct {
	GRPCPort int    `yaml:"grpc_port"`
	PKIDir   string `yaml:"pki_dir"`
}

// daemonConfigPath is the path to the daemon config file. Variable for testing.
var daemonConfigPath = "/etc/litevirt/config.yaml"

// LoadClusterConfig reads the cluster config.
// Priority: 1) LV_HOST env var → remote gRPC/mTLS mode
//  2. local daemon config at /etc/litevirt/config.yaml → local mode
func LoadClusterConfig() (*ClusterConfig, error) {
	// Explicit remote target always wins.
	if host := os.Getenv("LV_HOST"); host != "" {
		return &ClusterConfig{
			DefaultHost: host,
			GRPCPort:    7443,
			PKIDir:      PKIDir(),
		}, nil
	}

	// Check for local daemon config.
	if data, err := os.ReadFile(daemonConfigPath); err == nil {
		var dc localDaemonConfig
		if err := yaml.Unmarshal(data, &dc); err == nil {
			port := dc.GRPCPort
			if port == 0 {
				port = 7443
			}
			pkiDir := dc.PKIDir
			if pkiDir == "" {
				pkiDir = "/etc/litevirt/pki"
			}
			if cliPKIBundleExists(PKIDir()) {
				pkiDir = PKIDir()
			}
			return &ClusterConfig{
				GRPCPort: port,
				PKIDir:   pkiDir,
				Local:    true,
			}, nil
		}
	}

	return nil, fmt.Errorf("LV_HOST not set (set to host[:port] of any cluster node, or run on a litevirtd node)")
}

// Connect establishes a gRPC connection to a litevirtd instance.
// In local mode, connects directly to localhost with mTLS.
// In remote mode, connects directly to the configured gRPC endpoint with mTLS.
// Variable for testing — tests can override to inject a mock client.
var Connect = connectDefault

func connectDefault(ctx context.Context) (pb.LiteVirtClient, func(), error) {
	cfg, err := LoadClusterConfig()
	if err != nil {
		return nil, nil, err
	}

	if cfg.Local {
		return connectLocal(cfg)
	}
	return connectRemote(cfg)
}

// bearerToken implements grpc.PerRPCCredentials to inject a Bearer token.
type bearerToken struct {
	token string
}

func (b bearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearerToken) RequireTransportSecurity() bool { return true }

// resolveToken returns the active bearer token, if any.
// Priority: 1) LV_TOKEN env var  2) stored credential from `lv login`.
func resolveToken() string {
	if tok := os.Getenv("LV_TOKEN"); tok != "" {
		return tok
	}
	if cred, err := LoadCredential(); err == nil && cred != nil {
		return cred.Token
	}
	return ""
}

// tokenDialOption returns a grpc.DialOption that injects a Bearer token
// on every RPC, or nil if no token is available.
func tokenDialOption() grpc.DialOption {
	if tok := resolveToken(); tok != "" {
		return grpc.WithPerRPCCredentials(bearerToken{token: tok})
	}
	return nil
}

// withTokenOption appends the token dial option if a token is available.
func withTokenOption(opts []grpc.DialOption) []grpc.DialOption {
	if opt := tokenDialOption(); opt != nil {
		opts = append(opts, opt)
	}
	return opts
}

func connectLocal(cfg *ClusterConfig) (pb.LiteVirtClient, func(), error) {
	tlsCfg, err := pki.ClientTLSConfig(cfg.PKIDir)
	if err != nil {
		return nil, nil, fmt.Errorf("load local TLS config from %s: %w (expected a CLI client cert bundle in %s, or a readable daemon PKI dir)", cfg.PKIDir, err, PKIDir())
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GRPCPort)
	opts := withTokenOption([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	})
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("gRPC dial %s: %w", addr, err)
	}

	client := pb.NewLiteVirtClient(conn)
	closer := func() { conn.Close() }
	return client, closer, nil
}

func cliPKIBundleExists(dir string) bool {
	if !regularFile(filepath.Join(dir, "ca.crt")) {
		return false
	}
	return certKeyPairExists(dir, "client") || certKeyPairExists(dir, "host")
}

func certKeyPairExists(dir, name string) bool {
	return regularFile(filepath.Join(dir, name+".crt")) && regularFile(filepath.Join(dir, name+".key"))
}

func regularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func connectRemote(cfg *ClusterConfig) (pb.LiteVirtClient, func(), error) {
	// Parse LV_HOST: strip user@ prefix (backward compat), add port if missing.
	addr := cfg.DefaultHost
	if idx := strings.Index(addr, "@"); idx >= 0 {
		addr = addr[idx+1:]
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = fmt.Sprintf("%s:%d", addr, cfg.GRPCPort)
	}

	tlsCfg, err := pki.ClientTLSConfig(cfg.PKIDir)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS config: %w", err)
	}

	opts := withTokenOption([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	})
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("gRPC dial %s: %w", addr, err)
	}

	client := pb.NewLiteVirtClient(conn)
	closer := func() { conn.Close() }
	return client, closer, nil
}
