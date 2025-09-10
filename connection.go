package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func (state *AppState) getSSHConnection(cfg TunnelConfig, twoFACode string) (*ssh.Client, error) {
	key := fmt.Sprintf("%s@%s:%d", cfg.Auth.User, cfg.SSHHost, cfg.SSHPort)
	log.Printf("Getting SSH connection for %s", key)

	state.connMu.Lock()
	conn, exists := state.connections[key]
	if exists {
		log.Printf("Reusing SSH connection for %s", key)
		conn.mu.Lock()
		conn.refCount++
		conn.mu.Unlock()
		state.connMu.Unlock()
		return conn.client, nil
	}
	state.connMu.Unlock()

	client, err := dialSSH(cfg, twoFACode)
	if err != nil {
		return nil, err
	}

	state.connMu.Lock()
	state.connections[key] = &sshConnection{client: client, refCount: 1}
	state.connMu.Unlock()
	return client, nil
}

func dialViaHTTPProxy(p *ProxyConfig, targetAddr string) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	var conn net.Conn
	var err error
	if p.TLS {
		conn, err = tls.Dial("tcp", proxyAddr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("dial proxy failed: %w", err)
	}
	authLine := ""
	if p.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		authLine = fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", cred)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", targetAddr, targetAddr, authLine)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT failed: %w", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT status failed: %w", err)
	}
	if !strings.Contains(status, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, nil
}

func dialSSH(cfg TunnelConfig, twoFACode string) (*ssh.Client, error) {
	sshAddr := fmt.Sprintf("%s:%d", cfg.SSHHost, cfg.SSHPort)
	log.Printf("Attempting to connect to %s", sshAddr)
	auths := []ssh.AuthMethod{}
	if cfg.Auth.Use2FA {
		log.Printf("Using keyboard-interactive authentication (2FA enabled)")
		auths = []ssh.AuthMethod{ssh.KeyboardInteractive(kbdChallenge(cfg.Auth.Password, twoFACode))}
	} else {
		if cfg.Auth.Password != "" {
			log.Printf("Using password authentication for user %s", cfg.Auth.User)
			auths = append(auths, ssh.Password(cfg.Auth.Password))
		}
		if cfg.Auth.KeyPath != "" {
			log.Printf("Using key authentication from %s", cfg.Auth.KeyPath)
			pem, err := os.ReadFile(filepath.Clean(cfg.Auth.KeyPath))
			if err != nil {
				log.Printf("Failed to read key: %v", err)
				return nil, fmt.Errorf("read key: %w", err)
			}
			var signer ssh.Signer
			if cfg.Auth.KeyPassphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(cfg.Auth.KeyPassphrase))
			} else {
				signer, err = ssh.ParsePrivateKey(pem)
			}
			if err != nil {
				log.Printf("Failed to parse key: %v", err)
				return nil, fmt.Errorf("parse key: %w", err)
			}
			auths = append(auths, ssh.PublicKeys(signer))
		}
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication methods provided")
	}
	conf := &ssh.ClientConfig{
		User:            cfg.Auth.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	var client *ssh.Client
	if cfg.Proxy != nil && cfg.Proxy.Host != "" {
		log.Printf("Dialing via HTTP proxy %s:%d", cfg.Proxy.Host, cfg.Proxy.Port)
		conn, err := dialViaHTTPProxy(cfg.Proxy, sshAddr)
		if err != nil {
			log.Printf("Proxy dial failed: %v", err)
			return nil, err
		}
		log.Printf("Proxy connection established, performing SSH handshake")
		c, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, conf)
		if err != nil {
			conn.Close()
			log.Printf("SSH handshake failed: %v", err)
			return nil, fmt.Errorf("ssh handshake failed: %w", err)
		}
		client = ssh.NewClient(c, chans, reqs)
	} else {
		log.Printf("Direct dial to %s", sshAddr)
		var err error
		client, err = ssh.Dial("tcp", sshAddr, conf)
		if err != nil {
			log.Printf("Direct dial failed: %v", err)
			return nil, err
		}
	}
	log.Printf("Successfully connected to %s", sshAddr)
	return client, nil
}

func kbdChallenge(password, code string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		for i, q := range questions {
			ql := strings.ToLower(strings.TrimSpace(q))
			if strings.Contains(ql, "password") {
				answers[i] = password
			} else if strings.Contains(ql, "verification") || strings.Contains(ql, "code") || strings.Contains(ql, "token") || strings.Contains(ql, "authenticator") {
				answers[i] = code
			} else {
				return nil, fmt.Errorf("unexpected prompt: %s", q)
			}
		}
		return answers, nil
	}
}
