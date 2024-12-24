package testgenerate_backend_login

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
	"math/rand"
	"time"
)

var (
	secretKey = GetEnv("SECRET_KEY", "secretkey")
)

func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randInt(65, 90))
	}
	return string(bytes)
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

func hashRandomString() (randomStr, hashStr string) {
	randomStr = randomString(32)
	h := sha256.New()
	h.Write([]byte(randomStr))
	hashStr = hex.EncodeToString(h.Sum(nil))
	return
}

func dbRefreshTokenInsert(user_name, refreshUuid, userAgent, host string, expiresIn int64) error {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s"+
		" password=%s dbname=%s sslmode=disable",
		GetEnv("DB_HOST", "localhost"), GetEnvAsInt("DB_PORT", 5432),
		GetEnv("DB_USER", "postgres"), GetEnv("DB_PASSWORD", "pgpassword"), GetEnv("DB_NAME", "generate"))

	conn, err := pgx.Connect(context.Background(), psqlInfo)
	if err != nil {
		erRet := fmt.Errorf("dbRefreshTokenInsert. Unable to connect to database: %v\n", err)
		return erRet
	}
	defer conn.Close(context.Background())
	//_, errFiveSessions := conn.Exec(context.Background(), `select five_refresh_sessions($1)`, user_name)
	//if errFiveSessions != nil {
	//	return fmt.Errorf("Error DB function: five_refresh_sessions. %v\n", errFiveSessions)
	//}

	_, errIncert := conn.Exec(context.Background(), `insert into refresh_sessions(user_name, refresh_uuid, user_agent, host, expires_in, 
		create_time) values($1, $2, $3, $4, $5, $6)`, user_name, refreshUuid, userAgent, host, expiresIn, time.Now())
	if errIncert != nil {
		return fmt.Errorf("Error DB incert sessions: %v\n", errIncert)
	}

	return nil
}

func dbRefreshTokenGet(refreshUuid string) (username, role, useragent string, host string, expiresIn int64, err error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s"+
		" password=%s dbname=%s sslmode=disable",
		GetEnv("DB_HOST", "localhost"), GetEnvAsInt("DB_PORT", 5432),
		GetEnv("DB_USER", "postgres"), GetEnv("DB_PASSWORD", "password"), GetEnv("DB_NAME", "file"))

	conn, err := pgx.Connect(context.Background(), psqlInfo)
	if err != nil {
		erRet := fmt.Errorf("dbRefreshTokenGet. Unable to connect to database: %v\n", err)
		return username, role, useragent, host, expiresIn, erRet
	}
	defer conn.Close(context.Background())

	err = conn.QueryRow(context.Background(), `select user_name, user_agent, host, expires_in from refresh_sessions where refresh_uuid = $1`,
		refreshUuid).Scan(&username, &useragent, &host, &expiresIn)

	return username, role, useragent, host, expiresIn, err
}

func dbRefreshTokenDelete(refreshUuid string) error {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s"+
		" password=%s dbname=%s sslmode=disable",
		GetEnv("DB_HOST", "localhost"), GetEnvAsInt("DB_PORT", 5432),
		GetEnv("DB_USER", "postgres"), GetEnv("DB_PASSWORD", "password"), GetEnv("DB_NAME", "file"))

	conn, err := pgx.Connect(context.Background(), psqlInfo)
	if err != nil {
		erRet := fmt.Errorf("dbRefreshTokenDelete. Unable to connect to database: %v\n", err)
		return erRet
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(), `delete from refresh_sessions where refresh_uuid = $1`, refreshUuid)
	if err != nil {
		erRet := fmt.Errorf("dbRefreshTokenDelete. Exec: %v\n", err)
		return erRet
	}

	return nil
}

func dbGetUserRole(userName string) (role string, err error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s"+
		" password=%s dbname=%s sslmode=disable",
		GetEnv("DB_HOST", "localhost"), GetEnvAsInt("DB_PORT", 5432),
		GetEnv("DB_USER", "postgres"), GetEnv("DB_PASSWORD", "pgpassword"), GetEnv("DB_NAME", "generate"))
	conn, err := pgx.Connect(context.Background(), psqlInfo)
	if err != nil {
		erRet := fmt.Errorf("dbGetUserRole. Unable to connect to database: %v\n", err)
		return role, erRet
	}
	defer conn.Close(context.Background())

	err = conn.QueryRow(context.Background(), `select ur.role_name from users left join user_role ur on ur.id = users.role where users.user_name = $1`, userName).Scan(&role)
	return
}

//----------------------------------------------------------------------------------------------------------------------

func CreateToken(username, role, useragnet, ip string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 30).Unix()
	td.AccessUuid = uuid.New().String()

	td.RtExpires = time.Now().Add(time.Hour * 24).Unix()
	td.RefreshUuid = td.AccessUuid + "++" + username

	td.RandomString, td.Fingeprint = hashRandomString()

	//os.Setenv("ACCESS_SECRET", "accesssecret")

	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["username"] = username
	atClaims["role"] = role
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(secretKey))
	if err != nil {
		return nil, err
	}

	//insert into database resreshTokenTable
	err = dbRefreshTokenInsert(username, td.RefreshUuid, useragnet, ip, td.RtExpires)
	if err != nil {
		return nil, err
	}

	return td, nil
}

func ExtractTokenMetadata(token *jwt.Token) (AccessDetails, error) {
	ad := AccessDetails{}
	err := fmt.Errorf("error JWT Claims")
	claims, ok := token.Claims.(jwt.MapClaims)
	//fmt.Printf("%v\n", claims)
	if ok && token.Valid {
		name, ok := claims["username"].(string)
		if !ok {
			return ad, err
		}
		role, ok := claims["role"].(string)
		if !ok {
			return ad, err
		}
		return AccessDetails{
			UserName: name,
			UserRole: role,
		}, nil
	}
	return ad, err
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok || !token.Valid {
		return nil, errors.New("time is over")
	}
	return token, nil
}

func VerifyRefreshToken(newUseragent, newHost, username, role, refreshUuid, oldUa, oldHost string, oldExpiresin int64, logger *logrus.Logger) (TokenLogin, error) {
	err := dbRefreshTokenDelete(refreshUuid)
	if err != nil {
		logger.Debugf("Error delete refreshToken. %v\n", err)
		return TokenLogin{}, ErrInternal
	}
	timeExpires := time.Unix(oldExpiresin, 0)
	if time.Now().After(timeExpires) {
		logger.Debugf("Refresh Expires")
		return TokenLogin{}, ErrTokenExpire
	}

	//
	if (newUseragent != oldUa) || (newHost != oldHost) {
		logger.Debugf("Fraud refreshToken. User = %s\n", username)
		return TokenLogin{}, ErrInternal
	}

	tokenDetails, err := CreateToken(username, "admin", newUseragent, newHost)
	if err != nil {
		logger.Debugf("Error create token. Refreash session. Error = %v\n", err)
		return TokenLogin{}, ErrInternal
	}

	return TokenLogin{
		username,
		tokenDetails.AccessToken,
		tokenDetails.RefreshUuid,
		role,
	}, nil
}
