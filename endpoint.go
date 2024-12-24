package testgenerate_backend_login

import (
	"context"
	"errors"
	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	LoginEndpoint   endpoint.Endpoint
	CheckEndpoint   endpoint.Endpoint
	RefreshEndpoint endpoint.Endpoint
}

func (e Endpoints) Login(ctx context.Context, useragent, host string, creds Credential) (TokenLogin, error) {
	request := loginRequest{useragent, host, creds}
	response, err := e.LoginEndpoint(ctx, request)
	if err != nil {
		return TokenLogin{}, err
	}
	resp := response.(loginResponse)
	return resp.TokenLogin, errors.New(resp.Err)
}

func (e Endpoints) Check(ctx context.Context, token string) (AccessDetails, error) {
	ad := AccessDetails{}
	request := checkRequest{token}
	response, err := e.CheckEndpoint(ctx, request)
	if err != nil {
		return ad, err
	}
	resp := response.(checkResponse)
	return resp.AccessDetails, errors.New(resp.Err)
}

func (e Endpoints) Refresh(ctx context.Context, useragent, host, refreshuuid string) (TokenLogin, error) {
	request := refreshRequest{useragent: useragent, host: host, refreshuuid: refreshuuid}
	response, err := e.RefreshEndpoint(ctx, request)
	if err != nil {
		return TokenLogin{}, err
	}
	resp := response.(refreshResponse)
	return resp.TokenLogin, errors.New(resp.Err)
}

type loginRequest struct {
	useragent string
	host      string
	creds     Credential
}

type loginResponse struct {
	TokenLogin TokenLogin `json:"tokenlogin,omitempty"`
	Err        string     `json:"err,omitempty"`
}

type checkRequest struct {
	token string
}

type checkResponse struct {
	AccessDetails AccessDetails `json:"accessdetails,omitempty"`
	Err           string        `json:"err,omitempty"`
}

type refreshRequest struct {
	useragent   string
	host        string
	refreshuuid string
}

type refreshResponse struct {
	TokenLogin TokenLogin `json:"tokenlogin,omitempty"`
	Err        string     `json:"err,omitempty"`
}

// ------------------------------------------------------------------------

func MakeServerEndpoints(s Service) Endpoints {
	return Endpoints{
		LoginEndpoint:   MakeLoginEndpoint(s),
		CheckEndpoint:   MakeCheckEndpoint(s),
		RefreshEndpoint: MakeRefreshEndpoint(s),
	}
}

func MakeCheckEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(checkRequest)
		ad, e := s.Check(ctx, req.token)
		if e != nil {
			return checkResponse{ad, errors.Unwrap(e).Error()}, ErrTokenExpire
			//return checkResponse{ad, errors.Unwrap(e).Error()}, nil
		}
		return checkResponse{ad, ""}, nil
	}
}

func MakeLoginEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(loginRequest)
		tl, e := s.Login(ctx, req.useragent, req.host, req.creds)
		if e != nil {
			//return loginResponse{tl, e.Error()}, nil
			return loginResponse{tl, errors.Unwrap(e).Error()}, nil
		}
		return loginResponse{tl, ""}, nil
	}
}

func MakeRefreshEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(refreshRequest)
		tl, e := s.Refresh(ctx, req.useragent, req.host, req.refreshuuid)
		if e != nil {
			return refreshResponse{tl, "StatusUnauthorized"}, nil
		}
		return refreshResponse{tl, ""}, nil
	}
}
