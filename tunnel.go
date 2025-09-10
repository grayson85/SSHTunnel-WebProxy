package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

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
	// Set status to connecting at the start
	rt.Status = StatusConnecting
	rt.ErrorMsg = ""
	
	client, err := state.getSSHConnection(rt.Cfg, twoFACode)
	if err != nil {
		log.Printf("Failed to start tunnel: %v", err)
		rt.Status = StatusError
		rt.ErrorMsg = err.Error()
		return err
	}
	
	rt.Client = client
	rt.stopped = make(chan struct{})
	rt.LastHeartbeat = time.Now()

	// Try to set up all forwards
	for _, f := range rt.Cfg.Forwards {
		var setupErr error
		switch f.Type {
		case ForwardLocal:
			ln, err := net.Listen("tcp", f.LocalAddr)
			if err != nil {
				log.Printf("Failed to listen on %s: %v", f.LocalAddr, err)
				setupErr = fmt.Errorf("listen on %s failed: %w", f.LocalAddr, err)
			} else {
				log.Printf("Listening on %s", f.LocalAddr)
				rt.closers = append(rt.closers, ln)
				rt.wg.Add(1)
				safeGo(func() { rt.acceptLoop(ln, f.RemoteAddr, false) })
			}
		case ForwardRemote:
			rt.wg.Add(1)
			safeGo(func() { 
				if err := rt.remoteForward(f); err != nil {
					log.Printf("Remote forward failed: %v", err)
					rt.Status = StatusError
					rt.ErrorMsg = err.Error()
				}
			})
		case ForwardDynamic:
			rt.wg.Add(1)
			safeGo(func() { 
				if err := rt.dynamicForward(f.LocalAddr); err != nil {
					log.Printf("Dynamic forward failed: %v", err)
					rt.Status = StatusError
					rt.ErrorMsg = err.Error()
				}
			})
		}
		
		if setupErr != nil {
			rt.Status = StatusError
			rt.ErrorMsg = setupErr.Error()
			return setupErr
		}
	}
	
	// If we get here, all forwards were set up successfully
	rt.Status = StatusConnected
	rt.LastHeartbeat = time.Now()
	log.Printf("Tunnel successfully started for %s@%s:%d", rt.Cfg.Auth.User, rt.Cfg.SSHHost, rt.Cfg.SSHPort)
	
	return nil
}

func (rt *RunningTunnel) stop(state *AppState) {
	rt.mu.Lock()
	if rt.stopping {
		rt.mu.Unlock()
		return
	}
	rt.stopping = true
	rt.Status = StatusStopped
	rt.mu.Unlock()

	log.Printf("Stopping tunnel for %s@%s:%d", rt.Cfg.Auth.User, rt.Cfg.SSHHost, rt.Cfg.SSHPort)

	// Close all listeners first
	for _, c := range rt.closers {
		if c != nil {
			c.Close()
		}
	}

	// Handle SSH connection cleanup
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

	// Signal stopped and wait for goroutines
	if rt.stopped != nil {
		close(rt.stopped)
	}
	
	log.Printf("Tunnel stopped for %s@%s:%d", rt.Cfg.Auth.User, rt.Cfg.SSHHost, rt.Cfg.SSHPort)
}

func (rt *RunningTunnel) acceptLoop(ln net.Listener, remoteAddr string, dynamic bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Accept loop panic recovered: %v", r)
			rt.mu.Lock()
			if rt.Status == StatusConnected {
				rt.Status = StatusError
				rt.ErrorMsg = fmt.Sprintf("Accept loop crashed: %v", r)
			}
			rt.mu.Unlock()
		}
		rt.wg.Done()
	}()
	
	for {
		select {
		case <-rt.stopped:
			log.Printf("Accept loop stopping for %s", remoteAddr)
			return
		default:
		}
		
		conn, err := ln.Accept()
		if err != nil {
			if rt.isStopping() {
				return
			}
			log.Printf("Accept error: %v", err)
			// Don't set error status for temporary accept errors
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
	
	// Check if client is still valid
	if rt.Client == nil {
		log.Printf("SSH client is nil, cannot forward to %s", remoteAddr)
		return
	}
	
	rc, err := rt.Client.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Dial remote %s failed: %v", remoteAddr, err)
		// This could indicate connection issues
		rt.mu.Lock()
		if rt.Status == StatusConnected {
			rt.Status = StatusError
			rt.ErrorMsg = fmt.Sprintf("Failed to dial %s: %v", remoteAddr, err)
		}
		rt.mu.Unlock()
		return
	}
	defer rc.Close()
	
	log.Printf("Connected to remote %s", remoteAddr)
	rt.LastHeartbeat = time.Now() // Update heartbeat on successful connection
	
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
	
	// Check if client is still valid
	if rt.Client == nil {
		log.Printf("SSH client is nil, cannot SOCKS forward to %s", target)
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	
	rc, err := rt.Client.Dial("tcp", target)
	if err != nil {
		log.Printf("SOCKS dial to %s failed: %v", target, err)
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		// This could indicate connection issues
		rt.mu.Lock()
		if rt.Status == StatusConnected {
			rt.Status = StatusError
			rt.ErrorMsg = fmt.Sprintf("SOCKS dial failed: %v", err)
		}
		rt.mu.Unlock()
		return
	}
	defer rc.Close()
	
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	rt.LastHeartbeat = time.Now() // Update heartbeat on successful connection
	
	safeGo(func() { _, _ = io.Copy(rc, conn) })
	_, _ = io.Copy(conn, rc)
}

func (rt *RunningTunnel) remoteForward(f ForwardConfig) error {
	defer rt.wg.Done()
	
	if rt.Client == nil {
		return fmt.Errorf("SSH client is nil")
	}
	
	ln, err := rt.Client.Listen("tcp", f.RemoteAddr)
	if err != nil {
		log.Printf("Remote listen on %s failed: %v", f.RemoteAddr, err)
		return fmt.Errorf("remote listen on %s failed: %w", f.RemoteAddr, err)
	}
	defer ln.Close()
	
	log.Printf("Remote listening on %s", f.RemoteAddr)
	rt.acceptLoop(ln, f.LocalAddr, false)
	return nil
}

func (rt *RunningTunnel) dynamicForward(localAddr string) error {
	defer rt.wg.Done()
	
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Printf("Listen on %s failed: %v", localAddr, err)
		return fmt.Errorf("listen on %s failed: %w", localAddr, err)
	}
	defer ln.Close()
	
	rt.closers = append(rt.closers, ln)
	log.Printf("SOCKS proxy listening on %s", localAddr)
	rt.acceptLoop(ln, "", true)
	return nil
}

func (rt *RunningTunnel) isStopping() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.stopping
}

// Health check method to verify if the tunnel is still working
func (rt *RunningTunnel) isHealthy() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	if rt.Status != StatusConnected || rt.Client == nil {
		return false
	}
	
	// Check if it's been too long since last activity
	if time.Since(rt.LastHeartbeat) > 2*time.Minute {
		// Try a simple operation to verify connection
		session, err := rt.Client.NewSession()
		if err != nil {
			rt.Status = StatusDisconnected
			rt.ErrorMsg = "Connection lost"
			return false
		}
		session.Close()
		rt.LastHeartbeat = time.Now()
	}
	
	return true
}
