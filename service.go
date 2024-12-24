package testgenerate_backend_login

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-kit/kit/metrics"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
)

var (
	ErrCredentials       = errors.New("login/password is incorrect")
	ErrTokenExpire       = errors.New("token is expired")
	ErrRefreshSession    = errors.New("not found refresh session")
	ErrRefreshFingeprint = errors.New("RefreshUuid not condition")
	ErrInternal          = errors.New("internal error")
	ErrCreateToken       = errors.New("Ошибка авторизации. Проверьте данные и повторите попытку")
)

type Service interface {
	Login(ctx context.Context, useragent, host string, cred Credential) (TokenLogin, error)
	Check(ctx context.Context, token string) (AccessDetails, error)
	Refresh(ctx context.Context, useragent, host, tokenRefreshUuid string) (TokenLogin, error)
}

type loginservice struct {
	logger *logrus.Logger
}

func NewBasicService(logger *logrus.Logger) Service {
	return loginservice{
		logger: logger,
	}
}

func NewService(logger *logrus.Logger, requestCount metrics.Counter, requestLatency metrics.Histogram) Service {
	var svc Service
	{
		svc = NewBasicService(logger)
		svc = LoggingMiddleware(logger)(svc)
		svc = InstrumentingMiddleware(requestCount, requestLatency)(svc)
	}
	return svc
}

// --------------------------------------------------------------------------------------------------------------
func (ls loginservice) Login(ctx context.Context, useragent, host string, cred Credential) (tokenLogin TokenLogin, err error) {
	/*bcacert, err := base64.StdEncoding.DecodeString(GetEnv("LDAP_CA", "base64"))
	if err != nil {
		ErrI := fmt.Errorf("%w; Error get []byte from ENV LDAP_CA: %s", ErrInternal, err)
		return tokenLogin, ErrI
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(bcacert)

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	cfg := &ldap.Config{
		URL:          GetEnv("LDAP_URL", "cloudfare"),
		BindDN:       GetEnv("LDAP_BINDDN", ""),
		BaseDN:       GetEnv("LDAP_BASEDN", ""),
		BindPassword: GetEnv("LDAP_BINDPASSWORD", ""),
		Filter:       "(sAMAccountName=%s)", //GlobalConfigParam.LocalConfig.Ldap.Filter,
		TLS:          tlsConfig,
	}

	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		ErrInt := fmt.Errorf("%w; Error get request to LDAP: %s\n", ErrInternal, err)
		return tokenLogin, ErrInt
	}

	r.SetBasicAuth(cred.UserName, cred.Password)

	ls.logger.Debugln("Debug ldap auth.")

	ls.logger.Debugln("LDAP url == ", GetEnv("LDAP_URL", "cloudfare"))
	ls.logger.Debugln("LDAP BindDN == ", GetEnv("LDAP_BINDDN", ""))
	ls.logger.Debugln("LDAP BaseDN == ", GetEnv("LDAP_BASEDN", ""))
	ls.logger.Debugln("LDAP BindPassword == ", GetEnv("LDAP_BINDPASSWORD", ""))

	user, err := ldap.New(cfg).Authenticate(r.Context(), r)
	if err != nil {
		ls.logger.Debugf("Error dap.New(cfg).Authenticate(r.Context(), r). Message = %s\n", err.Error())
		ErrCredentialsResp := fmt.Errorf("%w; %s", ErrCredentials, err)
		return tokenLogin, ErrCredentialsResp
	}*/

	user := cred.UserName
	logrus.Info(user)
	//role, err := dbGetUserRole(user.GetUserName())
	role, err := dbGetUserRole(user)
	if err != nil {
		ErrGetUserRole := fmt.Errorf("%w; Error GetUserRole. Msg = %s", ErrCreateToken, err)
		return tokenLogin, ErrGetUserRole
	}

	//tokenDetails, err := CreateToken(user.GetUserName(), role, useragent, host)
	tokenDetails, err := CreateToken(user, role, useragent, host)
	if err != nil {
		ErrCreateTokenResp := fmt.Errorf("%w; Error CreateToken. Msg = %s", ErrCreateToken, err)
		return tokenLogin, ErrCreateTokenResp
	}

	tokenLogin = TokenLogin{
		//user.GetUserName(),
		user,
		tokenDetails.AccessToken,
		tokenDetails.RefreshUuid,
		role,
	}

	return tokenLogin, nil
}

func (loginservice) Check(ctx context.Context, token string) (accessDetail AccessDetails, err error) {
	jwtToken, err := VerifyToken(token)
	if err != nil {
		ErrTokenExpireResp := fmt.Errorf("%w; %s", ErrTokenExpire, err)
		return accessDetail, ErrTokenExpireResp
	}

	accessDetail, err = ExtractTokenMetadata(jwtToken)
	return
}

func (ls loginservice) Refresh(ctx context.Context, newUseragent, newHost, newTokenrefreshuuid string) (TokenLogin, error) {
	username, role, oldUa, oldHost, oldExpiresin, err := dbRefreshTokenGet(newTokenrefreshuuid)
	switch err {
	case pgx.ErrNoRows:
		return TokenLogin{}, ErrRefreshSession
	case nil:
		return VerifyRefreshToken(newUseragent, newHost, username, role, newTokenrefreshuuid, oldUa, oldHost, oldExpiresin, ls.logger)
	}
	ls.logger.Debugf("Service Refresh.dbRefreshTokenGet Error: %v\n", err)
	return TokenLogin{}, ErrInternal
}
