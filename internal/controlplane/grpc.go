package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/mcpids/mcpids/internal/auth"
	"github.com/mcpids/mcpids/internal/transport"
	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
)

// ServeGRPC starts the gRPC service-plane listener and blocks until ctx is cancelled.
func (s *Server) ServeGRPC(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.GRPCListenAddr)
	if err != nil {
		return fmt.Errorf("control-plane: gRPC listen %s: %w", s.cfg.GRPCListenAddr, err)
	}

	var serverOpts []grpc.ServerOption
	authenticator := auth.NewAuthenticator(s.cfg.Auth)
	serverOpts = append(serverOpts,
		grpc.ChainUnaryInterceptor(
			authenticator.UnaryServerInterceptor(),
			auth.RequireRolesUnary(s.cfg.Auth.AllowedRoles),
		),
		grpc.ChainStreamInterceptor(
			authenticator.StreamServerInterceptor(),
			auth.RequireRolesStream(s.cfg.Auth.AllowedRoles),
		),
	)
	if tlsCfg, err := transport.ServerTLSConfig(s.cfg.TLS); err != nil {
		ln.Close()
		return fmt.Errorf("control-plane: gRPC TLS config: %w", err)
	} else if tlsCfg != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(grpcServer, healthServer)
	mcpidsv1.RegisterInventoryServiceServer(grpcServer, s)
	mcpidsv1.RegisterPolicyServiceServer(grpcServer, s)
	mcpidsv1.RegisterEventServiceServer(grpcServer, s)
	mcpidsv1.RegisterApprovalServiceServer(grpcServer, s)

	slog.Info("control-plane: gRPC listening", "addr", s.cfg.GRPCListenAddr)

	errCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			grpcServer.Stop()
		}
		return nil
	case err := <-errCh:
		return err
	}
}
