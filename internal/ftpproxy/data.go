package ftpproxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

// dataPlan is one pending data channel: a locally allocated listener plus
// the peer endpoints to wire together. File contents are streamed through
// the proxy with fixed buffers; nothing is buffered on disk.
type dataPlan struct {
	s         *session
	mode      string // "active" (upstream connects in) or "passive" (client connects in)
	listener  *net.TCPListener
	bindIP    string // local address the listener is bound to
	advertise string // address advertised to the peer in PORT/EPRT/227
	localPort int

	// active: after upstream connects, dial the client endpoint.
	clientIP   string
	clientPort int
	// passive: after the client connects, dial the upstream endpoint.
	upIP   string
	upPort int

	once    sync.Once
	stopped bool
}

// newActivePlan handles a client PORT/EPRT: the client told us where it will
// listen; we open a local listener and advertise it to the upstream server.
func (s *session) newActivePlan(clientIP string, clientPort int) (*dataPlan, error) {
	plan, err := s.newPlan("active")
	if err != nil {
		return nil, err
	}
	plan.clientIP, plan.clientPort = clientIP, clientPort
	s.setPlan(plan)
	go s.runPlan(plan)
	return plan, nil
}

// newPassivePlan handles an intercepted 227/229: we remember the upstream
// data endpoint and open a local listener for the client.
func (s *session) newPassivePlan(upIP string, upPort int) (*dataPlan, error) {
	plan, err := s.newPlan("passive")
	if err != nil {
		return nil, err
	}
	plan.upIP, plan.upPort = upIP, upPort
	s.setPlan(plan)
	go s.runPlan(plan)
	return plan, nil
}

func (s *session) setPlan(plan *dataPlan) {
	s.mu.Lock()
	old := s.active
	if plan.mode == "passive" {
		old = s.passive
		s.passive = plan
	} else {
		s.active = plan
	}
	s.mu.Unlock()
	if old != nil {
		old.shutdown()
	}
}

// newPlan allocates the local TCP listener honoring data_bind_address,
// external_ip and the passive port range.
func (s *session) newPlan(mode string) (*dataPlan, error) {
	bindIP, advertise := s.bindAndAdvertise()
	ln, port, err := s.p.listenData(bindIP)
	if err != nil {
		return nil, err
	}
	return &dataPlan{
		s:         s,
		mode:      mode,
		listener:  ln,
		bindIP:    bindIP,
		advertise: advertise,
		localPort: port,
	}, nil
}

// bindAndAdvertise picks the bind address and the address put into
// PORT/EPRT/227 payloads.
func (s *session) bindAndAdvertise() (bindIP, advertise string) {
	controlLocal := ""
	if ta, ok := s.client.LocalAddr().(*net.TCPAddr); ok && ta.IP.To4() != nil {
		controlLocal = ta.IP.String()
	}
	switch {
	case s.p.extIP != nil && s.p.dataBind != nil:
		return s.p.dataBind.String(), s.p.extIP.String()
	case s.p.extIP != nil:
		return "0.0.0.0", s.p.extIP.String()
	case s.p.dataBind != nil:
		return s.p.dataBind.String(), s.p.dataBind.String()
	default:
		if controlLocal == "" {
			controlLocal = "0.0.0.0"
		}
		return controlLocal, controlLocal
	}
}

// listenData opens a tcp4 listener, honoring the configured passive port
// range when set.
func (p *Proxy) listenData(bindIP string) (*net.TCPListener, int, error) {
	lc := net.ListenConfig{}
	ctx := context.Background()
	if p.pLo > 0 {
		var lastErr error
		for i := 0; i < 32; i++ {
			port := p.pLo + rand.Intn(p.pHi-p.pLo+1)
			ln, err := lc.Listen(ctx, "tcp4", net.JoinHostPort(bindIP, strconv.Itoa(port)))
			if err == nil {
				return ln.(*net.TCPListener), port, nil
			}
			lastErr = err
		}
		return nil, 0, fmt.Errorf("no free data port in range %d-%d: %w", p.pLo, p.pHi, lastErr)
	}
	ln, err := lc.Listen(ctx, "tcp4", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		return nil, 0, err
	}
	return ln.(*net.TCPListener), ln.Addr().(*net.TCPAddr).Port, nil
}

// runPlan waits for exactly one peer connection on the local listener,
// wires both sides together and streams the transfer.
func (s *session) runPlan(plan *dataPlan) {
	defer s.closePlan(plan)

	deadline := time.Now().Add(s.p.cfg.DataAcceptTimeout.Duration)
	plan.listener.SetDeadline(deadline)
	peer, err := plan.listener.Accept()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			s.p.m.DataErrorsTotal.WithLabelValues(s.p.Name, "accept_timeout").Inc()
			s.log.Debug("data accept timeout", "mode", plan.mode, "cmd", s.getXferCmd(), "port", plan.localPort)
		}
		return
	}

	var clientSide, serverSide net.Conn
	dialCtx, cancel := context.WithTimeout(context.Background(), s.p.cfg.DialTimeout.Duration)
	defer cancel()
	// Pin the outgoing source address when configured (multi-homed hosts).
	d := net.Dialer{LocalAddr: localAddrOf(s.p.srcIP)}

	switch plan.mode {
	case "active":
		// The upstream FTP server dialed our listener; now dial the client.
		serverSide = peer
		clientSide, err = d.DialContext(dialCtx, "tcp4", hostPort(plan.clientIP, plan.clientPort))
	default:
		// The client dialed our listener; now dial the upstream server.
		clientSide = peer
		serverSide, err = d.DialContext(dialCtx, "tcp4", hostPort(plan.upIP, plan.upPort))
	}
	if err != nil {
		s.p.m.DataErrorsTotal.WithLabelValues(s.p.Name, "dial").Inc()
		s.log.Info("data connection dial failed", "mode", plan.mode, "cmd", s.getXferCmd(), "err", err)
		peer.Close()
		return
	}
	plan.listener.Close() // one-shot listener

	s.p.m.DataConnsTotal.WithLabelValues(s.p.Name, plan.mode).Inc()
	s.p.m.DataConnsActive.WithLabelValues(s.p.Name).Inc()
	s.transferCount.Add(1)
	defer func() {
		s.transferCount.Add(-1)
		s.p.m.DataConnsActive.WithLabelValues(s.p.Name).Dec()
	}()

	s.log.Debug("data connection established",
		"mode", plan.mode, "cmd", s.getXferCmd(),
		"client", clientSide.RemoteAddr().String(),
		"server", serverSide.RemoteAddr().String())

	start := time.Now()
	up, down := pipeData(s.log, clientSide, serverSide)
	clientSide.Close()
	serverSide.Close()
	if up > 0 {
		s.p.m.DataBytesTotal.WithLabelValues(s.p.Name, "upload").Add(float64(up))
	}
	if down > 0 {
		s.p.m.DataBytesTotal.WithLabelValues(s.p.Name, "download").Add(float64(down))
	}
	s.log.Info("data transfer finished", "cmd", s.getXferCmd(), "mode", plan.mode,
		"bytes_upload", up, "bytes_download", down)
	elapsed := time.Since(start).Seconds()
	s.p.m.DataSecondsHistogram.WithLabelValues(s.p.Name).Observe(elapsed)
}

func (s *session) closePlan(plan *dataPlan) {
	plan.once.Do(func() {
		plan.stopped = true
		plan.listener.Close()
	})
}

func (dp *dataPlan) shutdown() {
	dp.once.Do(func() {
		dp.stopped = true
		dp.listener.Close()
	})
}
