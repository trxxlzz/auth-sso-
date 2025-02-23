package app

import (
	grpcapp "auth-sso/internal/app/grpc"
	"auth-sso/internal/services/auth"
	"auth-sso/internal/storage/sqlite"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, storage, storage, storage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}

//func (a *App) MustRun() {
//	a.GRPCSrv.MustRun()
//}
