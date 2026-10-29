package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// InitListener must make the per-listener series visible on the registry
// before any traffic, so Prometheus sees zeros instead of absent series.
func TestInitListenerPrecreatesSeries(t *testing.T) {
	m := New("test", "none")
	m.InitListener("mylist")

	fams, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ftpproxy_sessions_total",
		"ftpproxy_control_connections_active",
		"ftpproxy_auth_failures_total",
		"ftpproxy_acl_denied_total",
		"ftpproxy_data_connections_total",
		"ftpproxy_data_connections_active",
		"ftpproxy_data_bytes_total",
		"ftpproxy_data_transfer_seconds",
	}
	got := map[string]bool{}
	for _, f := range fams {
		got[f.GetName()] = len(f.GetMetric()) > 0
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("%s missing or has no metrics after InitListener", name)
		}
	}

	// idempotent: second call must not panic or double-register
	m.InitListener("mylist")
	if _, err := m.registry.Gather(); err != nil {
		t.Fatal(err)
	}
	var _ prometheus.Registerer = m.registry
}
