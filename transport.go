package testgenerate_backend_login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"strings"
)

var (
	// ErrBadRouting is returned when an expected path variable is missing.
	// It always indicates programmer error.
	ErrBadRouting = errors.New("inconsistent mapping between route and handler (programmer error)")
)

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*fmt.Printf("HandlerFunc. r.Method == %v\n", r.Method)
		fmt.Printf("HandlerFunc. r.Origin == %v\n", r.Header.Get("Origin"))*/
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			//w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Origin, Accept, Content-Type, Content-Length, Accept-Encoding")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}

func MakeHTTPHandler(s Service) http.Handler {
	r := mux.NewRouter()
	e := MakeServerEndpoints(s)
	options := []httptransport.ServerOption{
		//httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logrus.Logger{})),
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("OPTIONS", "POST").Path("/auth").Handler(accessControl(httptransport.NewServer(
		e.LoginEndpoint,
		decodeLoginRequest,
		encodeResponse,
		options...,
	)))

	r.Methods("POST").Path("/refresh").Handler(accessControl(httptransport.NewServer(
		e.RefreshEndpoint,
		decodeRefreshRequest,
		encodeResponse,
		options...,
	)))

	r.Methods("GET").Path("/check").Handler(accessControl(httptransport.NewServer(
		e.CheckEndpoint,
		decodeCheckRequest,
		encodeResponse,
		options...,
	)))

	r.Methods("GET").Path("/metrics").Handler(promhttp.Handler())

	return r
}

func decodeLoginRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	var creds Credential
	//fmt.Printf("r.Body = %v\n", r.Body)
	if e := json.NewDecoder(r.Body).Decode(&creds); e != nil {
		fmt.Printf("Error auth decode r.Body == %s\n", e.Error())
		return nil, e
	}
	//fmt.Printf("creds = %v\n", creds)
	ip := r.Header.Get("x-forwarded-for")
	//fmt.Printf("%v\n", r.Header)
	//fmt.Printf("realIP == %s\n", ip)
	//host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return loginRequest{r.UserAgent(), ip, creds}, nil
}

func decodeCheckRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	//tokenString := r.Header.Get("Authorization")
	//fmt.Printf("tokenString == %s\n", tokenString)
	tb := strings.Split(r.Header.Get("Authorization"), " ")
	if len(tb) != 2 {
		//return checkRequest{}, errors.New("Not format Auzorization")
		return checkRequest{}, ErrCredentials
	}
	//fmt.Println("decodeCheckRequest: " + tokenString)
	return checkRequest{tb[1]}, nil
}

func decodeRefreshRequest(_ context.Context, r *http.Request) (request interface{}, err error) {
	//fmt.Printf("decodeRefreshRequest\n")
	var refresh RefreshToken
	if e := json.NewDecoder(r.Body).Decode(&refresh); e != nil {
		return nil, e
	}
	ip := r.Header.Get("x-forwarded-for")
	//fmt.Printf("decodeRefreshRequest. realIP == %s\n", ip)
	return refreshRequest{r.UserAgent(), ip, refresh.Refreshuuid}, nil
}

type errorer interface {
	error() error
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		// Not a Go kit transport error, but a business-logic error.
		// Provide those as HTTP errors.
		encodeError(ctx, e.error(), w)
		return nil
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

// --------------------------------------------------------------------------------------------------------------
func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		panic("encodeError with nil error")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(codeFrom(err))
	//w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

func codeFrom(err error) int {
	switch err {
	case ErrCredentials:
		return http.StatusUnauthorized
	case ErrTokenExpire:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}

}
