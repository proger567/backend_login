package main

import (
	"context"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	testgenerate "testgenerate_backend_login"
)

func LogLevel(lvl string) logrus.Level {
	switch strings.ToUpper(lvl) {
	case "INFO":
		return logrus.InfoLevel
	case "DEBUG":
		return logrus.DebugLevel
	case "TRACE":
		return logrus.TraceLevel
	case "ERROR":
		return logrus.ErrorLevel
	case "FATAL":
		return logrus.FatalLevel
	case "WARN":
		return logrus.WarnLevel
	default:
		panic("Not supported")
	}
}

func main() {
	logger := logrus.Logger{
		Out:   os.Stdout,
		Level: LogLevel(testgenerate.GetEnv("LOG_LEVEL", "INFO")),
		//ReportCaller: true,
		Formatter: &logrus.JSONFormatter{},
	}

	port := testgenerate.GetEnv("LISTEN_PORT", ":8090")

	fieldKeys := []string{"method", "error"}
	requestCount := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "api_test_generate",
		Subsystem: "login",
		Name:      "request_count",
		Help:      "Number of requests received.",
	}, fieldKeys)
	requestLatency := kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
		Namespace: "api_test_generate",
		Subsystem: "login",
		Name:      "request_latency_microseconds",
		Help:      "Total duration of requests in microseconds",
	}, fieldKeys)

	var (
		s = testgenerate.NewService(&logger, requestCount, requestLatency)
	)

	var h http.Handler
	{
		h = testgenerate.MakeHTTPHandler(s)
	}

	srv := &http.Server{
		Addr:    port,
		Handler: h,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Error during ListenAndServ(). ", err)
			//os.Exit(1)
		}
	}()

	time.Sleep(time.Second * 1)
	logger.Info("Start service. Listen HTTP port=", port)

	<-done
	logger.Info("Server stopped. Signal ")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server Exited error = ", err.Error())
	}
	logger.Info("Server Exited Properly")
}
