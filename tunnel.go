package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type RunningTunnel struct {
	Cfg      TunnelConfig
	Client   *ssh.Client
	closers  []io.Closer
	wg       sync.WaitGroup
	mu       sync.Mutex
	stopping bool
	stopped  chan struct{}
}

func safeGo(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered in goroutine: %v", r)
			}
		}()
		fn()
	}()
}

func (rt *RunningTunnel) start(twoFACode string, state *AppState) error {
	client, err := state.getSSHConnection(rt.Cfg, twoFACode)
	if err != nil {
		log.Printf("Failed to start tunnel: %v", err)
		return err
	}
	rt.Client = client
	rt.stopped = make(chan struct{})

	for _, f := range rt.Cfg.Forwards {
		switch f.Type {
		case ForwardLocal:
			ln, err := net.Listen("tcp", f.LocalAddr)
			if err != nil {
				log.Printf("Failed to listen on %s: %v", f.LocalAddr, err)
				return fmt.Errorf("listen on %s failed: %w", f.LocalAddr, err)
			}
			log.Printf("Listening on %s", f.LocalAddr)
			rt.closers = append(rt.closers, ln)
			rt.wg.Add(1)
			safeGo(func() { rt.acceptLoop(ln, f.RemoteAddr, false) })
		case ForwardRemote:
			rt.wg.Add(1)
			safeGo(func() { rt.remoteForward(f) })
		case ForwardDynamic:
			rt.wg.Add(1)
			safeGo(func() { rt.dynamicForward(f.LocalAddr) })
		}
	}
	return nil
}

func (rt *RunningTunnel) stop(state *AppState) {
	rt.mu.Lock()
	if rt.stopping {
		rt.mu.Unlock()
		return
	}
	rt.stopping = true
	rt.mu.Unlock()

	for _, c := range rt.closers {
		if c != nil {
			c.Close()
		}
	}

	if rt.Client != nil {
		key := fmt.Sprintf("%s@%s:%d", rt.Cfg.Auth.User, rt.Cfg.SSHHost, rt.Cfg.SSHPort)
		state.connMu.Lock()
		if conn, exists := state.connections[key]; exists {
			conn.mu.Lock()
			conn.refCount--
			if conn.refCount == 0 {
				log.Printf("Closing SSH connection for %s", key)
				rt.Client.Close()
				delete(state.connections, key)
			} else {
				log.Printf("Keeping SSH connection for %s (refCount: %d)", key, conn.refCount)
				rt.Client = nil // Avoid closing shared client
			}
			conn.mu.Unlock()
		}
		state.connMu.Unlock()
	}

	close(rt.stopped)
}

func (rt *RunningTunnel) acceptLoop(ln net.Listener, remoteAddr string, dynamic bool) {
	defer rt.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if rt.isStopping() {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())
		if dynamic {
			safeGo(func() { rt.handleSOCKS(conn) })
		} else {
			safeGo(func() { rt.handleDirectForward(conn, remoteAddr) })
		}
	}
}

func (rt *RunningTunnel) handleDirectForward(conn net.Conn, remoteAddr string) {
	defer conn.Close()
	log.Printf("Dialing remote %s", remoteAddr)
	rc, err := rt.Client.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Dial remote %s failed: %v", remoteAddr, err)
		return
	}
	defer rc.Close()
	log.Printf("Connected to remote %s", remoteAddr)
	safeGo(func() { _, _ = io.Copy(rc, conn) })
	_, _ = io.Copy(conn, rc)
}

func (rt *RunningTunnel) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		log.Printf("SOCKS handshake read failed: %v", err)
		return
	}
	if buf[0] != 5 {
		log.Printf("Invalid SOCKS version: %d", buf[0])
		return
	}
	_, _ = conn.Write([]byte{5, 0})
	n, err = conn.Read(buf)
	if err != nil || n < 10 {
		log.Printf("SOCKS request read failed: %v", err)
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		log.Printf("Invalid SOCKS request: version=%d, command=%d", buf[0], buf[1])
		return
	}
	var host string
	var port int
	switch buf[3] {
	case 1: // IPv4
		if n < 10 {
			log.Printf("Invalid SOCKS IPv4 request length: %d", n)
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = int(binary.BigEndian.Uint16(buf[8:10]))
	case 3: // Domain name
		if n < 7 {
			log.Printf("Invalid SOCKS domain request length: %d", n)
			return
		}
		hostLen := int(buf[4])
		if n < 5+hostLen+2 {
			log.Printf("Insufficient SOCKS domain request length: %d", n)
			return
		}
		host = string(buf[5 : 5+hostLen])
		port = int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))
	case 4: // IPv6
		log.Printf("SOCKS IPv6 not supported")
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	default:
		log.Printf("Unsupported SOCKS address type: %d", buf[3])
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	rc, err := rt.Client.Dial("tcp", target)
	if err != nil {
		log.Printf("SOCKS dial to %s failed: %v", target, err)
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer rc.Close()
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	safeGo(func() { _, _ = io.Copy(rc, conn) })
	_, _ = io.Copy(conn, rc)
}

func (rt *RunningTunnel) remoteForward(f ForwardConfig) {
	defer rt.wg.Done()
	ln, err := rt.Client.Listen("tcp", f.RemoteAddr)
	if err != nil {
		log.Printf("Remote listen on %s failed: %v", f.RemoteAddr, err)
		return
	}
	defer ln.Close()
	rt.acceptLoop(ln, f.LocalAddr, false)
}

func (rt *RunningTunnel) dynamicForward(localAddr string) {
	defer rt.wg.Done()
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("Listen on %s failed: %v", localAddr, err)
		return
	}
	defer ln.Close()
	rt.closers = append(rt.closers, ln)
	rt.acceptLoop(ln, "", true)
}

func (rt *RunningTunnel) isStopping() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.stopping
}