#!/usr/bin/env bash
# быстрая проверка установки ftproxy через systemd на debian/ubuntu
set -euo pipefail
cd "$(dirname "$0")/.."

sudo install -m 0755 bin/ftproxy-linux-amd64 /usr/local/bin/ftproxy
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ftproxy 2>/dev/null || true
sudo mkdir -p /etc/ftproxy

cat > /tmp/ftproxy-unit-test.yaml <<'YAML'
log:
  level: info
metrics:
  listen: "127.0.0.1:19107"
proxies:
  - name: unit
    listen: "127.0.0.1:12123"
    destination: "127.0.0.1:12023"
YAML
sudo install -m 0640 -o root -g ftproxy /tmp/ftproxy-unit-test.yaml /etc/ftproxy/config.yaml

sudo install -m 0644 deploy/ftproxy.service /etc/systemd/system/ftproxy.service
sudo systemctl daemon-reload

echo "--- verify ---"
systemd-analyze verify /etc/systemd/system/ftproxy.service 2>&1 || true

echo "--- start ---"
sudo systemctl reset-failed ftproxy 2>/dev/null || true
sudo systemctl start ftproxy
sleep 2
systemctl --no-pager --full status ftproxy | head -12 || true

echo "--- metrics ---"
curl -sf http://127.0.0.1:19107/healthz
curl -s http://127.0.0.1:19107/metrics | grep -c '^ftpproxy_' || true

echo "--- stop (graceful) ---"
sudo systemctl stop ftproxy
journalctl -u ftproxy --no-pager -n 6 || true
echo DONE
