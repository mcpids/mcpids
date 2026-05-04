// Package transport contains shared listener and TLS helpers.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/mcpids/mcpids/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// ServerTLSConfig builds a server tls.Config from component TLS settings.
// Returns nil when TLS is disabled.
func ServerTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("transport: cert_file and key_file are required when TLS is enabled")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: load server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	switch cfg.MTLSMode {
	case "required":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "optional":
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	default:
		tlsCfg.ClientAuth = tls.NoClientCert
	}

	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("transport: read ca_file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("transport: parse ca_file %q", cfg.CAFile)
		}
		tlsCfg.ClientCAs = caPool
	}

	return tlsCfg, nil
}

// ClientTLSConfig builds a client tls.Config for control-plane gRPC connections.
// Returns nil when TLS is disabled.
func ClientTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("transport: both cert_file and key_file are required for client mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("transport: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("transport: read ca_file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("transport: parse ca_file %q", cfg.CAFile)
		}
		tlsCfg.RootCAs = caPool
	}

	return tlsCfg, nil
}

// DialControlPlane opens a gRPC client connection to the control plane.
func DialControlPlane(ctx context.Context, cfg config.ControlPlaneClientConfig) (*grpc.ClientConn, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("transport: control_plane.address is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialOpts []grpc.DialOption
	if cfg.Insecure || !cfg.TLS.Enabled {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg, err := ClientTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}
	if cfg.BearerToken != "" {
		dialOpts = append(dialOpts,
			grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.BearerToken)
				return invoker(ctx, method, req, reply, cc, opts...)
			}),
			grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+cfg.BearerToken)
				return streamer(ctx, desc, cc, method, opts...)
			}),
		)
	}
	dialOpts = append(dialOpts, grpc.WithBlock())
	conn, err := grpc.DialContext(dialCtx, cfg.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("transport: dial control-plane %s: %w", cfg.Address, err)
	}
	return conn, nil
}
