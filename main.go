package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// ---- Tunnel & App Types ----

type ForwardType int

const (
	ForwardLocal ForwardType = iota // -L local:remote
	ForwardRemote                   // -R remote:local
	ForwardDynamic                  // -D dynamic SOCKS
)

func (ft ForwardType) String() string {
	switch ft {
	case ForwardLocal:
		return "Local"
	case ForwardRemote:
		return "Remote"
	case ForwardDynamic:
		return "Dynamic (SOCKS)"
	default:
		return "Unknown"
	}
}

type ForwardConfig struct {
	Type       ForwardType `json:"type"`
	LocalAddr  string      `json:"local_addr"`  // e.g. 127.0.0.1:8080
	RemoteAddr string      `json:"remote_addr"` // e.g. 127.0.0.1:80
}

type ProxyConfig struct {
	Host     string `json:"host"`     // proxy host (HTTP proxy)
	Port     int    `json:"port"`     // e.g. 80 or 3128 or 443
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"` // set true if HTTPS proxy (CONNECT over TLS)
}

type SSHAuthConfig struct {
	User          string `json:"user"`
	Password      string `json:"password"`       // optional, if using password auth
	KeyPath       string `json:"key_path"`       // optional, if using key auth
	KeyPassphrase string `json:"key_passphrase"` // optional passphrase for PEM key
	Use2FA        bool   `json:"use_2fa"`        // enable 2FA (keyboard-interactive)
}

type TunnelConfig struct {
	Name     string          `json:"name"`
	SSHHost  string          `json:"ssh_host"`
	SSHPort  int             `json:"ssh_port"`
	Auth     SSHAuthConfig   `json:"auth"`
	Proxy    *ProxyConfig    `json:"proxy,omitempty"` // nil if not using web proxy
	Forwards []ForwardConfig `json:"forwards"`
}

type RunningTunnel struct {
	Cfg      TunnelConfig
	Client   *ssh.Client
	closers  []io.Closer
	wg       sync.WaitGroup
	mu       sync.Mutex
	stopping bool
	stopped  chan struct{}
}

// ---- Core Networking Logic ----

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

	// HTTP CONNECT with optional auth
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
	
	// Consume remaining headers
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, nil
}

func kbdChallenge(password, twoFACode string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		for i, q := range questions {
			ql := strings.ToLower(strings.TrimSpace(q))
			if strings.Contains(ql, "password") {
				answers[i] = password
			} else if strings.Contains(ql, "verification") || strings.Contains(ql, "code") || strings.Contains(ql, "token") || strings.Contains(ql, "authenticator") {
				answers[i] = twoFACode
			} else {
				return nil, fmt.Errorf("unexpected prompt: %s", q)
			}
		}
		return answers, nil
	}
}

func dialSSH(cfg TunnelConfig, twoFACode string) (*ssh.Client, error) {
    sshAddr := net.JoinHostPort(cfg.SSHHost, strconv.Itoa(cfg.SSHPort))
    log.Printf("Attempting to connect to %s", sshAddr)
    auths := []ssh.AuthMethod{}

    if cfg.Auth.Use2FA {
		log.Printf("Using keyboard-interactive authentication only (2FA enabled)")
		auths = []ssh.AuthMethod{
			ssh.KeyboardInteractive(kbdChallenge(cfg.Auth.Password, twoFACode)),
		}
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

    sshConf := &ssh.ClientConfig{
        User:            cfg.Auth.User,
        Auth:            auths,
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         15 * time.Second,
    }

    var client *ssh.Client
    var err error
    if cfg.Proxy != nil && cfg.Proxy.Host != "" {
        log.Printf("Dialing via HTTP proxy %s:%d", cfg.Proxy.Host, cfg.Proxy.Port)
        conn, err := dialViaHTTPProxy(cfg.Proxy, sshAddr)
        if err != nil {
            log.Printf("Proxy dial failed: %v", err)
            return nil, err
        }
        log.Printf("Proxy connection established, performing SSH handshake")
        c, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, sshConf)
        if err != nil {
            conn.Close()
            log.Printf("SSH handshake failed: %v", err)
            return nil, fmt.Errorf("ssh handshake failed: %w", err)
        }
        client = ssh.NewClient(c, chans, reqs)
    } else {
        log.Printf("Direct dial to %s", sshAddr)
        client, err = ssh.Dial("tcp", sshAddr, sshConf)
        if err != nil {
            log.Printf("Direct dial failed: %v", err)
            return nil, err
        }
    }

    log.Printf("Successfully connected to %s", sshAddr)
    return client, nil
}

func (rt *RunningTunnel) start(twoFACode string) error {
    client, err := dialSSH(rt.Cfg, twoFACode)
    if err != nil {
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
			safeGo(func() { rt.acceptLoop(ln, f.RemoteAddr, false) }) // FIX
            // go rt.acceptLoop(ln, f.RemoteAddr, false)
        case ForwardRemote:
            rt.wg.Add(1)
			safeGo(func() { rt.remoteForward(f) }) // FIX
            // go rt.remoteForward(f)
        case ForwardDynamic:
            rt.wg.Add(1)
			safeGo(func() { rt.dynamicForward(f.LocalAddr) }) // FIX
            // go rt.dynamicForward(f.LocalAddr)
        }
    }
    return nil
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
            // go rt.handleSOCKS(conn)
			safeGo(func() { rt.handleSOCKS(conn) }) // FIX
        } else {
            // go rt.handleDirectForward(conn, remoteAddr)
			safeGo(func() { rt.handleDirectForward(conn, remoteAddr) }) // FIX
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
    go func() { _, _ = io.Copy(rc, conn) }()
    _, _ = io.Copy(conn, rc)
}

// Basic SOCKS5 implementation
func (rt *RunningTunnel) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	
	// SOCKS5 handshake
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return
	}
	
	if buf[0] != 5 { // SOCKS version 5
		return
	}
	
	// No authentication required
	_, _ = conn.Write([]byte{5, 0})
	
	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 10 {
		return
	}
	
	if buf[0] != 5 || buf[1] != 1 { // CONNECT command
		return
	}
	
	var host string
	var port int
	
	switch buf[3] { // Address type
	case 1: // IPv4
		if n < 10 {
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = int(binary.BigEndian.Uint16(buf[8:10]))
	case 3: // Domain name
		if n < 7 {
			return
		}
		hostLen := int(buf[4])
		if n < 5+hostLen+2 {
			return
		}
		host = string(buf[5 : 5+hostLen])
		port = int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))
	case 4: // IPv6 - not implemented
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	default:
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}
	
	target := net.JoinHostPort(host, strconv.Itoa(port))
	rc, err := rt.Client.Dial("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}
	defer rc.Close()
	
	// Success response
	_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	
	// Relay data
	go func() { _, _ = io.Copy(rc, conn) }()
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

func (rt *RunningTunnel) stop() {
	rt.mu.Lock()
	if rt.stopping {
		rt.mu.Unlock()
		return
	}
	rt.stopping = true
	rt.mu.Unlock()
	
	// Close all listeners
	for _, c := range rt.closers {
		if c != nil {
			c.Close()
		}
	}
	
	// Close SSH client
	if rt.Client != nil {
		rt.Client.Close()
	}
	
	// Signal stopped and wait briefly
	close(rt.stopped)
	
	// Don't wait for WaitGroup - let goroutines finish naturally
	// This prevents hanging the UI thread
}

// ---- Persistent Config ----
func saveConfigFile(cfgs []TunnelConfig, file string) error {
	data, err := json.MarshalIndent(cfgs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

func loadConfigFile(file string) ([]TunnelConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return []TunnelConfig{}, nil // Return empty slice if file doesn't exist
	}
	var cfgs []TunnelConfig
	err = json.Unmarshal(data, &cfgs)
	return cfgs, err
}

// ---- GUI ----
type AppState struct {
	configs      []TunnelConfig
	running      map[int]*RunningTunnel
	list         *widget.List
	status       *widget.Label
	selectedIdx  int
}

func (state *AppState) refreshList() {
	state.list.Refresh()
}

func (state *AppState) updateStatus() {
	runningCount := len(state.running)
	if runningCount == 0 {
		state.status.SetText("Ready")
	} else {
		state.status.SetText(fmt.Sprintf("Ready • %d tunnel(s) running", runningCount))
	}
}

func (state *AppState) addTunnelDialog(w fyne.Window, configFile string) {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("My SSH Tunnel")
	
	sshHostEntry := widget.NewEntry()
	sshHostEntry.SetPlaceHolder("abc.com")
	
	sshPortEntry := widget.NewEntry()
	sshPortEntry.SetText("22")
	
	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("SSH Username")
	
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("SSH Password (optional)")
	
	keyPathEntry := widget.NewEntry()
	keyPathEntry.SetPlaceHolder("/path/to/ssh/key (optional)")
	
	use2FACheck := widget.NewCheck("Enable 2FA", nil)
	
	localAddrEntry := widget.NewEntry()
	localAddrEntry.SetPlaceHolder("127.0.0.1:1234")
	
	remoteAddrEntry := widget.NewEntry()
	remoteAddrEntry.SetPlaceHolder("123.123.123.123:22")
	
	forwardTypeSelect := widget.NewSelect([]string{"Local", "Remote", "Dynamic (SOCKS)"}, nil)
	forwardTypeSelect.SetSelected("Local")
	
	// Proxy settings
	useProxyCheck := widget.NewCheck("Use HTTP Proxy (for restricted networks)", nil)
	proxyHostEntry := widget.NewEntry()
	proxyHostEntry.SetPlaceHolder("proxy.company.com")
	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText("80")
	proxyUserEntry := widget.NewEntry()
	proxyUserEntry.SetPlaceHolder("proxy_username")
	proxyPassEntry := widget.NewPasswordEntry()
	proxyPassEntry.SetPlaceHolder("proxy_password")
	proxyTLSCheck := widget.NewCheck("HTTPS Proxy", nil)
	
	items := []*widget.FormItem{
		{Text: "Name:", Widget: nameEntry},
		{Text: "SSH Host:", Widget: sshHostEntry},
		{Text: "SSH Port:", Widget: sshPortEntry},
		{Text: "Username:", Widget: userEntry},
		{Text: "Password:", Widget: passwordEntry},
		{Text: "Key Path:", Widget: keyPathEntry},
		{Text: "", Widget: use2FACheck},
		{Text: "Forward Type:", Widget: forwardTypeSelect},
		{Text: "Local Port:", Widget: localAddrEntry},
		{Text: "Target:", Widget: remoteAddrEntry},
		{Text: "", Widget: useProxyCheck},
		{Text: "Proxy Host:", Widget: proxyHostEntry},
		{Text: "Proxy Port:", Widget: proxyPortEntry},
		{Text: "Proxy User:", Widget: proxyUserEntry},
		{Text: "Proxy Pass:", Widget: proxyPassEntry},
		{Text: "", Widget: proxyTLSCheck},
	}
	
	dialog.ShowForm("Add Tunnel", "Create", "Cancel", items, func(confirm bool) {
		if !confirm {
			return
		}
		
		port, _ := strconv.Atoi(sshPortEntry.Text)
		if port == 0 {
			port = 22
		}
		
		var forwardType ForwardType
		switch forwardTypeSelect.Selected {
		case "Remote":
			forwardType = ForwardRemote
		case "Dynamic (SOCKS)":
			forwardType = ForwardDynamic
		default:
			forwardType = ForwardLocal
		}
		
		var proxy *ProxyConfig
		if useProxyCheck.Checked {
			proxyPort, _ := strconv.Atoi(proxyPortEntry.Text)
			if proxyPort == 0 {
				proxyPort = 8080
			}
			proxy = &ProxyConfig{
				Host:     proxyHostEntry.Text,
				Port:     proxyPort,
				Username: proxyUserEntry.Text,
				Password: proxyPassEntry.Text,
				TLS:      proxyTLSCheck.Checked,
			}
		}
		
		cfg := TunnelConfig{
			Name:    nameEntry.Text,
			SSHHost: sshHostEntry.Text,
			SSHPort: port,
			Auth: SSHAuthConfig{
				User:     userEntry.Text,
				Password: passwordEntry.Text,
				KeyPath:  keyPathEntry.Text,
				Use2FA:   use2FACheck.Checked,
			},
			Proxy: proxy,
			Forwards: []ForwardConfig{{
				Type:       forwardType,
				LocalAddr:  localAddrEntry.Text,
				RemoteAddr: remoteAddrEntry.Text,
			}},
		}
		
		state.configs = append(state.configs, cfg)
		if err := saveConfigFile(state.configs, configFile); err != nil {
			dialog.ShowError(err, w)
			return
		}
		state.refreshList()
	}, w)
}

func (state *AppState) editSelected(w fyne.Window, configFile string) {
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.configs) {
		dialog.ShowInformation("No Selection", "Please select a tunnel to edit.", w)
		return
	}
	
	idx := state.selectedIdx
	cfg := state.configs[idx]
	
	nameEntry := widget.NewEntry()
	nameEntry.SetText(cfg.Name)
	
	sshHostEntry := widget.NewEntry()
	sshHostEntry.SetText(cfg.SSHHost)
	
	sshPortEntry := widget.NewEntry()
	sshPortEntry.SetText(strconv.Itoa(cfg.SSHPort))
	
	userEntry := widget.NewEntry()
	userEntry.SetText(cfg.Auth.User)
	
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText(cfg.Auth.Password)
	
	keyPathEntry := widget.NewEntry()
	keyPathEntry.SetText(cfg.Auth.KeyPath)
	
	use2FACheck := widget.NewCheck("Enable 2FA", nil)
	use2FACheck.SetChecked(cfg.Auth.Use2FA)
	
	var localAddr, remoteAddr string
	var forwardType ForwardType
	if len(cfg.Forwards) > 0 {
		localAddr = cfg.Forwards[0].LocalAddr
		remoteAddr = cfg.Forwards[0].RemoteAddr
		forwardType = cfg.Forwards[0].Type
	}
	
	localAddrEntry := widget.NewEntry()
	localAddrEntry.SetText(localAddr)
	
	remoteAddrEntry := widget.NewEntry()
	remoteAddrEntry.SetText(remoteAddr)
	
	forwardTypeSelect := widget.NewSelect([]string{"Local", "Remote", "Dynamic (SOCKS)"}, nil)
	forwardTypeSelect.SetSelected(forwardType.String())
	
	// ADD PROXY CONFIGURATION FIELDS
	useProxyCheck := widget.NewCheck("Use HTTP Proxy (for restricted networks)", nil)
	proxyHostEntry := widget.NewEntry()
	proxyHostEntry.SetPlaceHolder("proxy.company.com")
	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText("80")
	proxyUserEntry := widget.NewEntry()
	proxyUserEntry.SetPlaceHolder("proxy_username")
	proxyPassEntry := widget.NewPasswordEntry()
	proxyPassEntry.SetPlaceHolder("proxy_password")
	proxyTLSCheck := widget.NewCheck("HTTPS Proxy", nil)
	
	// Load existing proxy settings if they exist
	if cfg.Proxy != nil {
		useProxyCheck.SetChecked(true)
		proxyHostEntry.SetText(cfg.Proxy.Host)
		proxyPortEntry.SetText(strconv.Itoa(cfg.Proxy.Port))
		proxyUserEntry.SetText(cfg.Proxy.Username)
		proxyPassEntry.SetText(cfg.Proxy.Password)
		proxyTLSCheck.SetChecked(cfg.Proxy.TLS)
	}
	
	items := []*widget.FormItem{
		{Text: "Name:", Widget: nameEntry},
		{Text: "SSH Host:", Widget: sshHostEntry},
		{Text: "SSH Port:", Widget: sshPortEntry},
		{Text: "Username:", Widget: userEntry},
		{Text: "Password:", Widget: passwordEntry},
		{Text: "Key Path:", Widget: keyPathEntry},
		{Text: "", Widget: use2FACheck},
		{Text: "Forward Type:", Widget: forwardTypeSelect},
		{Text: "Local Address:", Widget: localAddrEntry},
		{Text: "Remote Address:", Widget: remoteAddrEntry},
		// ADD PROXY FIELDS TO THE FORM
		{Text: "", Widget: useProxyCheck},
		{Text: "Proxy Host:", Widget: proxyHostEntry},
		{Text: "Proxy Port:", Widget: proxyPortEntry},
		{Text: "Proxy User:", Widget: proxyUserEntry},
		{Text: "Proxy Pass:", Widget: proxyPassEntry},
		{Text: "", Widget: proxyTLSCheck},
	}
	
	dialog.ShowForm("Edit Tunnel", "Save", "Cancel", items, func(confirm bool) {
		if !confirm {
			return
		}
		
		port, _ := strconv.Atoi(sshPortEntry.Text)
		if port == 0 {
			port = 22
		}
		
		var fwdType ForwardType
		switch forwardTypeSelect.Selected {
		case "Remote":
			fwdType = ForwardRemote
		case "Dynamic (SOCKS)":
			fwdType = ForwardDynamic
		default:
			fwdType = ForwardLocal
		}
		
		// HANDLE PROXY CONFIGURATION
		var proxy *ProxyConfig
		if useProxyCheck.Checked {
			proxyPort, _ := strconv.Atoi(proxyPortEntry.Text)
			if proxyPort == 0 {
				proxyPort = 8080
			}
			proxy = &ProxyConfig{
				Host:     proxyHostEntry.Text,
				Port:     proxyPort,
				Username: proxyUserEntry.Text,
				Password: proxyPassEntry.Text,
				TLS:      proxyTLSCheck.Checked,
			}
		}
		
		state.configs[idx] = TunnelConfig{
			Name:    nameEntry.Text,
			SSHHost: sshHostEntry.Text,
			SSHPort: port,
			Auth: SSHAuthConfig{
				User:     userEntry.Text,
				Password: passwordEntry.Text,
				KeyPath:  keyPathEntry.Text,
				Use2FA:   use2FACheck.Checked,
			},
			Proxy: proxy, // Use the new proxy configuration instead of keeping the old one
			Forwards: []ForwardConfig{{
				Type:       fwdType,
				LocalAddr:  localAddrEntry.Text,
				RemoteAddr: remoteAddrEntry.Text,
			}},
		}
		
		if err := saveConfigFile(state.configs, configFile); err != nil {
			dialog.ShowError(err, w)
			return
		}
		state.refreshList()
	}, w)
}

func (state *AppState) deleteSelected(configFile string) {
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.configs) {
		return
	}
	
	idx := state.selectedIdx
	
	// Stop tunnel if running
	if rt, exists := state.running[idx]; exists {
		rt.stop()
		delete(state.running, idx)
	}
	
	// Remove from configs
	state.configs = append(state.configs[:idx], state.configs[idx+1:]...)
	
	// Reset selection if we deleted the selected item
	if state.selectedIdx == idx {
		state.selectedIdx = -1
	} else if state.selectedIdx > idx {
		state.selectedIdx--
	}
	
	// Update indices in running map
	newRunning := make(map[int]*RunningTunnel)
	for i, rt := range state.running {
		if i > idx {
			newRunning[i-1] = rt
		} else if i < idx {
			newRunning[i] = rt
		}
	}
	state.running = newRunning
	
	_ = saveConfigFile(state.configs, configFile)
	state.refreshList()
	state.updateStatus()
}

func (state *AppState) startSelected(w fyne.Window) {
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.configs) {
		return
	}
	
	idx := state.selectedIdx
	
	if _, exists := state.running[idx]; exists {
		state.status.SetText("Tunnel already running")
		return
	}
	
	cfg := state.configs[idx]
	rt := &RunningTunnel{Cfg: cfg}
	
	if cfg.Auth.Use2FA {
		codeEntry := widget.NewEntry()
		codeEntry.SetPlaceHolder("Enter 2FA code")
		
		d := dialog.NewForm("2FA Required", "Connect", "Cancel", []*widget.FormItem{
			{Text: "Code:", Widget: codeEntry},
		}, func(confirm bool) {
			if !confirm {
				return
			}
			
			twoFACode := codeEntry.Text
			if twoFACode == "" {
				dialog.ShowError(fmt.Errorf("2FA code cannot be empty"), w)
				return
			}
			
			state.status.SetText("Starting tunnel...")
			go func() {
				if err := rt.start(twoFACode); err != nil {
					state.status.SetText(fmt.Sprintf("Failed to start tunnel: %v", err))
					return
				}
				state.running[idx] = rt
				state.updateStatus()
				state.refreshList()
			}()
		}, w)
		d.Show()
	} else {
		state.status.SetText("Starting tunnel...")
		go func() {
			if err := rt.start(""); err != nil {
				state.status.SetText(fmt.Sprintf("Failed to start tunnel: %v", err))
				return
			}
			state.running[idx] = rt
			state.updateStatus()
			state.refreshList()
		}()
	}
}

func (state *AppState) stopSelected() {
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.configs) {
		return
	}
	
	idx := state.selectedIdx
	rt, exists := state.running[idx]
	if !exists {
		state.status.SetText("Tunnel not running")
		return
	}
	
	// Stop immediately without goroutines to avoid crashes
	state.status.SetText("Stopping tunnel...")
	rt.stop()
	delete(state.running, idx)
	state.updateStatus()
	state.refreshList()
}

func main() {
	a := app.New()
	w := a.NewWindow("SSH Tunnels + Web Proxy @GraysonLee - v1.0")
	w.Resize(fyne.NewSize(980, 620))
	
	configFile := "tunnels.json"
	state := &AppState{
		running:     make(map[int]*RunningTunnel),
		selectedIdx: -1,
	}
	
	// Load existing configs
	cfgs, err := loadConfigFile(configFile)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
	}
	state.configs = cfgs

// Create list widget
	state.list = widget.NewList(
		func() int {
			return len(state.configs)
		},
		func() fyne.CanvasObject {
			dot := canvas.NewCircle(color.NRGBA{R: 200, G: 0, B: 0, A: 255})
			dot.Resize(fyne.NewSize(8, 8)) // Set a reasonable size for the circle
			
			// Create a container with padding to ensure the circle is visible
			dotContainer := container.NewWithoutLayout(dot)
			dotContainer.Resize(fyne.NewSize(20, 32)) // Container size
			
			// Position the circle in the center of the container
			dot.Move(fyne.NewPos(2, 15)) // Center the 12x12 circle in 20x20 container

			lbl := widget.NewLabel("Tunnel")
			return container.NewHBox(dotContainer, lbl)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(state.configs) {
				return
			}
			cfg := state.configs[i]
			row := o.(*fyne.Container)

			// Get the dot container and then the circle inside it
			dotContainer := row.Objects[0].(*fyne.Container)
			dot := dotContainer.Objects[0].(*canvas.Circle)
			lbl := row.Objects[1].(*widget.Label)

			if _, running := state.running[i]; running {
				dot.FillColor = color.NRGBA{R: 0, G: 200, B: 0, A: 255} // green for running
			} else {
				dot.FillColor = color.NRGBA{R: 200, G: 0, B: 0, A: 255} // red for stopped
			}
			dot.Refresh()

			lbl.SetText(fmt.Sprintf("%s (%s:%d)", cfg.Name, cfg.SSHHost, cfg.SSHPort))
		},
	)

	// Handle list selection
	state.list.OnSelected = func(id widget.ListItemID) {
		state.selectedIdx = id
	}
	
	state.list.OnUnselected = func(id widget.ListItemID) {
		state.selectedIdx = -1
	}

	// Create buttons
	btnAdd := widget.NewButton("Add Tunnel", func() {
		state.addTunnelDialog(w, configFile)
	})
	
	btnEdit := widget.NewButton("Edit", func() {
		state.editSelected(w, configFile)
	})
	
	btnDelete := widget.NewButton("Delete", func() {
		state.deleteSelected(configFile)
	})
	
	btnStart := widget.NewButton("Start", func() {
		state.startSelected(w)
	})
	
	btnStop := widget.NewButton("Stop", func() {
		state.stopSelected()
	})

	// Status label
	state.status = widget.NewLabel("Ready")
	state.updateStatus()

	// Layout
	buttons := container.NewHBox(btnAdd, btnEdit, btnDelete, btnStart, btnStop)
	content := container.NewBorder(
		nil,                                              // top
		container.NewVBox(buttons, state.status),        // bottom
		nil,                                              // left
		nil,                                              // right
		state.list,                                       // center
	)

	w.SetContent(content)
	w.ShowAndRun()
}