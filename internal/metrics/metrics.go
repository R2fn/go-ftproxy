// Package metrics exposes Prometheus metrics for the FTP proxy.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all registered collectors. The "listener" label equals the
// proxy listener name from the configuration.
type Metrics struct {
	registry *prometheus.Registry

	SessionsTotal        *prometheus.CounterVec   // ftpproxy_sessions_total{listener}
	SessionsActive       *prometheus.GaugeVec     // ftpproxy_control_connections_active{listener}
	ErrorsTotal          *prometheus.CounterVec   // ftpproxy_errors_total{listener,reason}
	CommandsTotal        *prometheus.CounterVec   // ftpproxy_commands_total{listener,command}
	AuthFailuresTotal    *prometheus.CounterVec   // ftpproxy_auth_failures_total{listener}
	ACLDeniedTotal       *prometheus.CounterVec   // ftpproxy_acl_denied_total{listener}
	DataConnsTotal       *prometheus.CounterVec   // ftpproxy_data_connections_total{listener,mode}
	DataConnsActive      *prometheus.GaugeVec     // ftpproxy_data_connections_active{listener}
	DataErrorsTotal      *prometheus.CounterVec   // ftpproxy_data_errors_total{listener,reason}
	DataBytesTotal       *prometheus.CounterVec   // ftpproxy_data_bytes_total{listener,direction}
	DataSecondsHistogram *prometheus.HistogramVec // ftpproxy_data_transfer_seconds{listener}
	BuildInfo            *prometheus.GaugeVec     // ftpproxy_build_info{version,revision}
}

// New creates and registers all metrics on a private registry.
func New(version, revision string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{registry: reg}

	m.SessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "sessions_total",
		Help: "Client control connections accepted by the listener.",
	}, []string{"listener"})

	m.SessionsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ftpproxy", Name: "control_connections_active",
		Help: "Currently open client control connections.",
	}, []string{"listener"})

	m.ErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "errors_total",
		Help: "Control-session errors by reason (acl_denied|auth_denied|upstream_dial|client_read|server_read...).",
	}, []string{"listener", "reason"})

	m.CommandsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "commands_total",
		Help: "FTP commands seen on the control channel.",
	}, []string{"listener", "command"})

	m.AuthFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "auth_failures_total",
		Help: "Failed proxy-side authentications.",
	}, []string{"listener"})

	m.ACLDeniedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "acl_denied_total",
		Help: "Connections denied by ACL.",
	}, []string{"listener"})

	m.DataConnsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "data_connections_total",
		Help: "Proxy-side data connections established (mode: active|passive).",
	}, []string{"listener", "mode"})

	m.DataConnsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ftpproxy", Name: "data_connections_active",
		Help: "Currently active data transfers.",
	}, []string{"listener"})

	m.DataErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "data_errors_total",
		Help: "Data connection failures by reason (accept_timeout|dial|copy...).",
	}, []string{"listener", "reason"})

	m.DataBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ftpproxy", Name: "data_bytes_total",
		Help: "Bytes relayed on data connections, counted when a direction finishes.",
	}, []string{"listener", "direction"})

	m.DataSecondsHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "ftpproxy", Name: "data_transfer_seconds",
		Help:    "Duration of data transfers.",
		Buckets: []float64{0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 900, 3600, 14400, 72000, 288000},
	}, []string{"listener"})

	m.BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ftpproxy", Name: "build_info",
		Help: "Build information, always 1.",
	}, []string{"version", "revision"})
	m.BuildInfo.WithLabelValues(version, revision).Set(1)

	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		m.SessionsTotal, m.SessionsActive, m.ErrorsTotal, m.CommandsTotal,
		m.AuthFailuresTotal, m.ACLDeniedTotal, m.DataConnsTotal, m.DataConnsActive,
		m.DataErrorsTotal, m.DataBytesTotal, m.DataSecondsHistogram, m.BuildInfo,
	)
	return m
}

// InitListener pre-creates the per-listener series with zero values so that
// /metrics exposes them from startup, before the first connection arrives.
// Missing series would be indistinguishable from "no data scraped" in
// Prometheus. Two-label vectors (errors_total, commands_total) are left lazy:
// their label sets are only known at runtime.
func (m *Metrics) InitListener(name string) {
	m.SessionsTotal.WithLabelValues(name).Add(0)
	m.SessionsActive.WithLabelValues(name).Set(0)
	m.AuthFailuresTotal.WithLabelValues(name).Add(0)
	m.ACLDeniedTotal.WithLabelValues(name).Add(0)
	m.DataConnsTotal.WithLabelValues(name, "passive").Add(0)
	m.DataConnsTotal.WithLabelValues(name, "active").Add(0)
	m.DataConnsActive.WithLabelValues(name).Set(0)
	m.DataBytesTotal.WithLabelValues(name, "upload").Add(0)
	m.DataBytesTotal.WithLabelValues(name, "download").Add(0)
	_ = m.DataSecondsHistogram.WithLabelValues(name)
}

// Handler serves the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
