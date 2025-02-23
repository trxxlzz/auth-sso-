package auth

import (
	"auth-sso/internal/domain/models"
	"auth-sso/internal/lib/jwt"
	"auth-sso/internal/storage"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, password []byte) (uid int64, err error) // на регу входит пароль не в стринге
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
)

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:         log,
		usrSaver:    userSaver,
		usrProvider: userProvider,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, appID int) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	if email == "" {
		a.log.Warn("email is required but missing")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if appID == 0 {
		a.log.Warn("appID is required but missing")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		a.log.Error("failed to get user", slog.String("error", err.Error()))

		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.log.Error("failed to get user", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if user.PassHash == nil {
		a.log.Warn("user has no password set")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	a.log.Info("Checking password hash", slog.String("password", password))

	if user.PassHash == nil {
		a.log.Warn("user has no password set")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	a.log.Info("Stored hash", slog.String("hash", string(user.PassHash)))

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials")

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil || app == (models.App{}) {
		a.log.Warn("app not found or invalid appID")
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token")

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "Auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email))

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to generate password hash")

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists")

			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("failed to save user")

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")

	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	IsAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		errors.Is(err, storage.ErrAppNotFound)
		{
			log.Warn("user not found")

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}

	}

	log.Info("checked if user is admin", slog.Bool("is_admin", IsAdmin))

	return IsAdmin, nil
}
