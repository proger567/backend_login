package testgenerate_backend_login

import (
	"context"
	"fmt"
	"github.com/go-kit/kit/metrics"
	"github.com/sirupsen/logrus"
	"time"
)

type Middleware func(Service) Service

func LoggingMiddleware(logger *logrus.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   Service
	logger *logrus.Logger
}

func (mw loggingMiddleware) Login(ctx context.Context, useragent, host string, creds Credential) (tokenLogin TokenLogin, err error) {
	defer func(begin time.Time) {
		mw.logger.WithFields(logrus.Fields{
			"uri":   host,
			"user":  creds.UserName,
			"took":  time.Since(begin),
			"error": err,
		}).Info("method", "Login")
	}(time.Now())
	return mw.next.Login(ctx, useragent, host, creds)
}

func (mw loggingMiddleware) Check(ctx context.Context, token string) (accessDetails AccessDetails, err error) {
	defer func(begin time.Time) {
		mw.logger.WithFields(logrus.Fields{
			"token": token,
			"took":  time.Since(begin),
			"error": err,
		}).Info("method", "Check")
	}(time.Now())
	return mw.next.Check(ctx, token)
}

func (mw loggingMiddleware) Refresh(ctx context.Context, newUseragent, newHost, newTokenrefreshuuid string) (tokenLogin TokenLogin, err error) {
	defer func(begin time.Time) {
		mw.logger.WithFields(logrus.Fields{
			"token": newTokenrefreshuuid,
			"took":  time.Since(begin),
			"error": err,
		}).Info("method", "Refresh")
	}(time.Now())
	return mw.next.Refresh(ctx, newUseragent, newHost, newTokenrefreshuuid)
}

// -------------------------------------------------------------------------------------------------------------------

func InstrumentingMiddleware(requestCount metrics.Counter, requestLatency metrics.Histogram) Middleware {
	return func(next Service) Service {
		return instrumentingMiddleware{
			requestCount,
			requestLatency,
			next,
		}
	}
}

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

func (mw instrumentingMiddleware) Login(ctx context.Context, useragent, host string, creds Credential) (tokenLogin TokenLogin, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "login", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())
	tokenLogin, err = mw.next.Login(ctx, useragent, host, creds)
	return
}

func (mw instrumentingMiddleware) Check(ctx context.Context, token string) (accessDetails AccessDetails, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "check", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())
	accessDetails, err = mw.next.Check(ctx, token)
	return
}

func (mw instrumentingMiddleware) Refresh(ctx context.Context, newUseragent, newHost, newTokenrefreshuuid string) (tokenLogin TokenLogin, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "refresh", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())
	tokenLogin, err = mw.next.Refresh(ctx, newUseragent, newHost, newTokenrefreshuuid)
	return
}
