// ftproxy — transparent IPv4 FTP proxy with ACL, optional proxy-side
// authentication, Prometheus metrics and configurable logging.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/r2fn/go-ftproxy/internal/config"
	"github.com/r2fn/go-ftproxy/internal/dnsx"
	"github.com/r2fn/go-ftproxy/internal/ftpproxy"
	"github.com/r2fn/go-ftproxy/internal/logging"
	"github.com/r2fn/go-ftproxy/internal/metrics"
)

// Set via -ldflags at build time.
var (
	version  = "dev"
	revision = "none"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ftproxy %s (%s)\n", version, revision)
		return
	}
	if err := run(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "ftproxy: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	log, closeLog, err := logging.Setup(cfg.Log)
	if err != nil {
		return err
	}
	defer closeLog()

	m := metrics.New(version, revision)

	res := dnsx.New(cfg.DNS)
	if cfg.DNS.Resolver != "" {
		log.Info("using custom DNS resolver", "resolver", cfg.DNS.Resolver, "cache_ttl", cfg.DNS.CacheTTL.Duration)
	} else {
		log.Info("using system DNS resolver", "cache_ttl", cfg.DNS.CacheTTL.Duration)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxies := make([]*ftpproxy.Proxy, 0, len(cfg.Proxies))
	defer func() {
		for _, p := range proxies {
			p.Shutdown()
		}
	}()
	for _, pc := range cfg.Proxies {
		p, err := ftpproxy.New(pc, res, m, log, cfg.Log)
		if err != nil {
			return err
		}
		proxies = append(proxies, p)
	}

	var metricsSrv *http.Server
	if cfg.Metrics.Listen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok\n"))
		})
		metricsSrv = &http.Server{Addr: cfg.Metrics.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("metrics listening", "listen", cfg.Metrics.Listen)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server", "err", err)
			}
		}()
	}

	srvErr := make(chan error, len(proxies))
	for _, p := range proxies {
		go func(p *ftpproxy.Proxy) {
			if err := p.Serve(ctx); err != nil {
				srvErr <- err
			}
		}(p)
	}

	log.Info("ftproxy started", "version", version, "listeners", len(proxies), "pid", os.Getpid())

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-srvErr:
		stop()
		for _, p := range proxies {
			p.Shutdown()
		}
		if metricsSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			metricsSrv.Shutdown(shutCtx)
		}
		return fmt.Errorf("listener failed: %w", err)
	}

	for _, p := range proxies {
		p.Shutdown()
	}
	if metricsSrv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsSrv.Shutdown(shutCtx); err != nil {
			log.Warn("metrics server shutdown", "err", err)
		}
	}
	log.Info("ftproxy stopped")
	return nil
}
