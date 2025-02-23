package grpcapp

import (
	authgrpc "auth-sso/internal/grpc/auth"
	"auth-sso/internal/services/auth"
	"fmt"
	"google.golang.org/grpc"
	"log/slog"
	"net"
)

type App struct {
	log        *slog.Logger
	GRPCServer *grpc.Server
	port       int
}

func New(log *slog.Logger, auth *auth.Auth, port int) *App {
	gRPCServer := grpc.NewServer()

	authgrpc.Register(gRPCServer, auth)

	return &App{
		log:        log,
		GRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("starting gRPC server", slog.String("address", l.Addr().String()))

	if err := a.GRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).
		Info("stopping gRPC server", slog.Int("port", a.port))

	a.GRPCServer.GracefulStop()
}
