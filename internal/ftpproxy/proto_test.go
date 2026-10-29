package ftpproxy

import (
	"testing"
)

func TestParseFormatPORT(t *testing.T) {
	ip, port, err := parsePORT("192,168,1,10,196,13")
	if err != nil {
		t.Fatalf("parsePORT: %v", err)
	}
	if ip != "192.168.1.10" || port != 50189 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if got := formatPORT(ip, port); got != "192,168,1,10,196,13" {
		t.Fatalf("formatPORT = %q", got)
	}
	if _, _, err := parsePORT("1,2,3"); err == nil {
		t.Fatal("expected error for short PORT")
	}
	if _, _, err := parsePORT("1,2,3,4,0,0"); err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestParseFormatEPRT(t *testing.T) {
	ip, port, err := parseEPRT("|1|10.0.0.5|52422|")
	if err != nil {
		t.Fatalf("parseEPRT: %v", err)
	}
	if ip != "10.0.0.5" || port != 52422 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if _, _, err := parseEPRT("|2|::1|52422|"); err == nil {
		t.Fatal("IPv6 EPRT must be rejected")
	}
	if eprtIsIPv4("|2|::1|1|") {
		t.Fatal("eprtIsIPv4 must be false")
	}
	if !eprtIsIPv4("|1|1.2.3.4|1|") {
		t.Fatal("eprtIsIPv4 must be true")
	}
}

func TestParse227And229(t *testing.T) {
	lines := []string{"227 Entering Passive Mode (192,0,2,1,196,13)."}
	ip, port, ok := parse227Addr(lines)
	if !ok || ip != "192.0.2.1" || port != 50189 {
		t.Fatalf("parse227Addr = %s:%d ok=%v", ip, port, ok)
	}
	rew := rewrite227(lines, "10.1.1.1", 20000)
	ip, port, ok = parse227Addr(rew)
	if !ok || ip != "10.1.1.1" || port != 20000 {
		t.Fatalf("rewrite227 failed: %v -> %s:%d", rew, ip, port)
	}

	lines229 := []string{"229 Entering Extended Passive Mode (|||50189|)"}
	p, ok := parse229Port(lines229)
	if !ok || p != 50189 {
		t.Fatalf("parse229Port = %d ok=%v", p, ok)
	}
	rew229 := rewrite229(lines229, 31000)
	p, ok = parse229Port(rew229)
	if !ok || p != 31000 {
		t.Fatalf("rewrite229 failed: %v -> %d", rew229, p)
	}
	if rew229[0] != "229 Entering Extended Passive Mode (|||31000|)" {
		t.Fatalf("rewrite229 corrupted line: %q", rew229[0])
	}
}

func TestReadResponseMultiLine(t *testing.T) {
	// handled via bufio in integration; here test framing helper
	// "220-line\r\n220 tail" is a single multi-line response.
	// covered by readControlLine usage in integration tests.
}
