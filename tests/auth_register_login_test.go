package tests

import (
	"auth-sso/tests/suite"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ssov1 "github.com/trxxlzz/protos/gen/go/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"testing"
	"time"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	fmt.Printf("Claims: %+v\n", claims)
	idVal, ok := claims["uid"]
	require.True(t, ok, "uid not found in claims")

	idFloat, ok := idVal.(float64)
	require.True(t, ok, "id is not float64")

	id := int64(idFloat)
	assert.Equal(t, respReg.GetUserId(), id)

	assert.Equal(t, email, claims["email"].(string))

	appIDVal, ok := claims["app_id"]
	require.True(t, ok, "app_id not found in claims")

	appIDFloat, ok := appIDVal.(float64)
	require.True(t, ok, "app_id is not float64")

	appIDInt := int(appIDFloat)
	assert.Equal(t, appID, appIDInt)

	const deltaSeconds = 1

	fmt.Printf("loginTime: %v, exp: %v\n", loginTime.Add(st.Cfg.TokenTTl).Unix(), claims["exp"])
	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTl).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_RegisterDuplication(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomFakePassword()

	log.Printf("📌 [TEST] Calling Register with email=%s", email)
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	log.Printf("📌 [TEST] First Register response: %+v, err: %v", respReg, err)
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	log.Printf("📌 [TEST] Calling Register again with the same email=%s", email)

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})

	log.Printf("📌 [TEST] Second Register response: %+v, err: %v", respReg, err)

	assert.Empty(t, respReg.GetUserId())
	assert.Equal(t, codes.AlreadyExists, status.Code(err))

	log.Println("✅ [TEST] TestRegisterLogin_RegisterDuplication passed successfully!")
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with empty password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password required",
		},
		{
			name:        "Login with empty email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "email required",
		},
		{
			name:        "Login with both empty",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "email required",
		},
		{
			name:        "Login with Non-Matching password",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid email or password",
		},
		{
			name:        "Login without AppID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: "app_id required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			t.Logf("📌 [TEST] Trying to login with email=%s, password=%s, appID=%d", tt.email, tt.password, tt.appID)

			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})

			t.Logf("📌 [TEST] Login response: err=%v", err)

			require.Error(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})

			t.Logf("📌 [TEST] Login test case: %s | Expected error: %s | Actual error: %v", tt.name, tt.expectedErr, err)

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with empty password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "password required",
		},
		{
			name:        "Register with empty email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "email required",
		},
		{
			name:        "Register with both empty",
			email:       "",
			password:    "",
			expectedErr: "email required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
