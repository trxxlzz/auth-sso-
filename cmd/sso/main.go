package main

import (
	"auth-sso/internal/app"
	_ "auth-sso/internal/app/grpc"
	"auth-sso/internal/config"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const (
	EnvLocal = "local"
	EnvProd  = "prod"
	EnvDev   = "dev"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)

	log := SetupLogger(cfg.Env)

	log.Info("starting application")

	application := app.New(log, cfg.GRPC.Port, cfg.Storage_path, cfg.TokenTTl)

	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	<-stop

	application.GRPCSrv.Stop()

	log.Info("application stopped")
}
func SetupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case EnvLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case EnvProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case EnvDev:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
