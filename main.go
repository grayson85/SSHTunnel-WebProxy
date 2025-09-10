package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("SSH Tunnels + Web Proxy @GraysonLee - v2.0")
	w.Resize(fyne.NewSize(980, 620))

	configFile := "tunnels.json"
	state := &AppState{
		running:     make(map[int]*RunningTunnel),
		selectedIdx: -1,
		connections: make(map[string]*sshConnection),
	}

	// Load configs
	cfgs, err := loadConfigFile(configFile)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
	}
	state.configs = cfgs

	// List with enhanced status display
	state.list = widget.NewList(
		func() int { return len(state.configs) },
		func() fyne.CanvasObject {
			dot := canvas.NewCircle(theme.ErrorColor())
			dot.Resize(fyne.NewSize(8, 8))
			dotContainer := container.NewWithoutLayout(dot)
			dotContainer.Resize(fyne.NewSize(20, 32))
			dot.Move(fyne.NewPos(2, 15))
			lbl := widget.NewLabel("Tunnel")
			return container.NewHBox(dotContainer, lbl)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			updateListItem(i, o, state)
		},
	)

	state.list.OnSelected = func(id widget.ListItemID) { state.selectedIdx = id }
	state.list.OnUnselected = func(id widget.ListItemID) { state.selectedIdx = -1 }

	// Buttons
	btnAdd := widget.NewButton("Add Tunnel", func() { state.addTunnelDialog(w, configFile) })
	btnEdit := widget.NewButton("Edit", func() { state.editSelected(w, configFile) })
	btnDelete := widget.NewButton("Delete", func() { state.deleteSelected(configFile) })
	btnStart := widget.NewButton("Start", func() { state.startSelected(w) })
	btnStop := widget.NewButton("Stop", func() { state.stopSelected() })

	state.status = widget.NewLabel("Ready")
	state.updateStatus()

	// Start connection monitoring
	state.startStatusMonitoring()

	buttons := container.NewHBox(btnAdd, btnEdit, btnDelete, btnStart, btnStop)
	content := container.NewBorder(nil, container.NewVBox(buttons, state.status), nil, nil, state.list)

	w.SetContent(content)
	
	// Cleanup when window closes
	w.SetOnClosed(func() {
		state.cleanup()
	})
	
	w.ShowAndRun()
}

// Enhanced list item update with status colors and text
func updateListItem(i widget.ListItemID, o fyne.CanvasObject, state *AppState) {
	if i >= len(state.configs) {
		return
	}
	cfg := state.configs[i]
	row := o.(*fyne.Container)
	dotContainer := row.Objects[0].(*fyne.Container)
	dot := dotContainer.Objects[0].(*canvas.Circle)
	lbl := row.Objects[1].(*widget.Label)

	if rt, running := state.running[i]; running {
		switch rt.Status {
		case StatusConnecting:
			dot.FillColor = theme.WarningColor() // Yellow/Orange for connecting
		case StatusConnected:
			dot.FillColor = theme.SuccessColor() // Green for connected
		case StatusError, StatusDisconnected:
			dot.FillColor = theme.ErrorColor() // Red for error/disconnected
		default:
			dot.FillColor = theme.ErrorColor()
		}
		
		statusText := fmt.Sprintf("%s (%s:%d) - %s", 
			cfg.Name, cfg.SSHHost, cfg.SSHPort, rt.Status.String())
		if rt.Status == StatusError && rt.ErrorMsg != "" {
			statusText += fmt.Sprintf(" [%s]", rt.ErrorMsg)
		}
		lbl.SetText(statusText)
	} else {
		dot.FillColor = theme.ErrorColor() // Red for stopped
		lbl.SetText(fmt.Sprintf("%s (%s:%d)", cfg.Name, cfg.SSHHost, cfg.SSHPort))
	}
	
	dot.Refresh()
}

func (state *AppState) refreshList() {
	if state.list != nil {
		state.list.Refresh()
	}
}

func (state *AppState) updateStatus() {
	status := "Ready"
	if len(state.running) > 0 {
		connected := 0
		connecting := 0
		errors := 0
		
		for _, rt := range state.running {
			switch rt.Status {
			case StatusConnected:
				connected++
			case StatusConnecting:
				connecting++
			case StatusError, StatusDisconnected:
				errors++
			}
		}
		
		statusParts := []string{}
		if connected > 0 {
			statusParts = append(statusParts, fmt.Sprintf("%d connected", connected))
		}
		if connecting > 0 {
			statusParts = append(statusParts, fmt.Sprintf("%d connecting", connecting))
		}
		if errors > 0 {
			statusParts = append(statusParts, fmt.Sprintf("%d error", errors))
		}
		
		if len(statusParts) > 0 {
			status = fmt.Sprintf("Tunnels: %s", statusParts[0])
			for i := 1; i < len(statusParts); i++ {
				status += ", " + statusParts[i]
			}
		}
	}
	state.status.SetText(status)
}

func (state *AppState) startSelected(w fyne.Window) {
	if state.selectedIdx < 0 || state.selectedIdx >= len(state.configs) {
		return
	}
	idx := state.selectedIdx
	if rt, exists := state.running[idx]; exists && rt.Status == StatusConnected {
		state.status.SetText("Tunnel already running")
		return
	}
	
	cfg := state.configs[idx]
	rt := &RunningTunnel{
		Cfg:    cfg,
		Status: StatusConnecting,
	}
	state.running[idx] = rt
	
	// Immediately refresh to show "connecting" status
	state.refreshList()
	state.updateStatus()
	
	var twoFACode string
	key := fmt.Sprintf("%s@%s:%d", cfg.Auth.User, cfg.SSHHost, cfg.SSHPort)
	
	if _, exists := state.connections[key]; !exists && cfg.Auth.Use2FA {
		codeEntry := widget.NewEntry()
		codeEntry.SetPlaceHolder("Enter 2FA code")
		d := dialog.NewForm("2FA Required", "Connect", "Cancel", []*widget.FormItem{
			{Text: "Code:", Widget: codeEntry},
		}, func(confirm bool) {
			if !confirm {
				// User cancelled - remove from running
				delete(state.running, idx)
				state.updateStatus()
				state.refreshList()
				return
			}
			twoFACode = codeEntry.Text
			if twoFACode == "" {
				rt.Status = StatusError
				rt.ErrorMsg = "2FA code cannot be empty"
				state.refreshList()
				state.updateStatus()
				return
			}
			
			state.status.SetText("Connecting...")
			go state.attemptConnection(idx, twoFACode)
		}, w)
		d.Show()
	} else {
		state.status.SetText("Connecting...")
		go state.attemptConnection(idx, "")
	}
}

func (state *AppState) attemptConnection(idx int, twoFACode string) {
	rt := state.running[idx]
	
	// Your existing connection logic here
	err := rt.start(twoFACode, state) // Your existing start method
	
	if err != nil {
		rt.Status = StatusError
		rt.ErrorMsg = err.Error()
		state.status.SetText(fmt.Sprintf("Failed to connect: %v", err))
	} else {
		rt.Status = StatusConnected
		rt.LastHeartbeat = time.Now()
		state.status.SetText("Tunnel connected successfully")
	}
	
	state.updateStatus()
	state.refreshList()
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
	
	state.status.SetText("Stopping tunnel...")
	rt.Status = StatusStopped
	rt.stop(state) // Your existing stop method
	delete(state.running, idx)
	state.updateStatus()
	state.refreshList()
}

func (state *AppState) startStatusMonitoring() {
	state.statusTicker = time.NewTicker(5 * time.Second) // Check every 5 seconds
	
	go func() {
		for range state.statusTicker.C {
			state.checkConnectionHealth()
		}
	}()
}

func (state *AppState) checkConnectionHealth() {
	needsRefresh := false
	
	for _, rt := range state.running {
		if rt.Status == StatusConnected {
			// Check if connection is still healthy
			if !state.isConnectionHealthy(rt) {
				rt.Status = StatusDisconnected
				rt.ErrorMsg = "Connection lost"
				needsRefresh = true
			} else {
				rt.LastHeartbeat = time.Now()
			}
		}
	}
	
	if needsRefresh {
		state.refreshList()
		state.updateStatus()
	}
}

func (state *AppState) isConnectionHealthy(rt *RunningTunnel) bool {
	if rt.Client == nil {
		return false
	}
	
	// Try to create a simple session to test if connection is alive
	session, err := rt.Client.NewSession()
	if err != nil {
		log.Printf("Health check failed for %s@%s:%d: %v", rt.Cfg.Auth.User, rt.Cfg.SSHHost, rt.Cfg.SSHPort, err)
		return false
	}
	session.Close()
	
	return true
}

func (state *AppState) cleanup() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic in cleanup recovered: %v", r)
		}
	}()

	if state.statusTicker != nil {
		state.statusTicker.Stop()
	}
	
	// Stop all running tunnels with error handling
	for idx, rt := range state.running {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Panic stopping tunnel %d: %v", idx, r)
				}
			}()
			rt.stop(state)
		}()
	}
	
	// Close all connections with error handling
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic closing connections: %v", r)
			}
		}()
		
		state.connMu.Lock()
		defer state.connMu.Unlock()
		
		for key, conn := range state.connections {
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Panic closing connection %s: %v", key, r)
					}
				}()
				
				if conn != nil && conn.client != nil {
					conn.client.Close()
				}
			}()
		}
		
		// Clear the connections map
		state.connections = make(map[string]*sshConnection)
	}()
}

// Keep all your existing dialog functions (addTunnelDialog, editSelected, deleteSelected)
// These remain the same as in your original code

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
	keyPassEntry := widget.NewPasswordEntry()
	keyPassEntry.SetPlaceHolder("Key Passphrase (optional)")
	use2FACheck := widget.NewCheck("Enable 2FA", nil)
	localAddrEntry := widget.NewEntry()
	localAddrEntry.SetPlaceHolder("127.0.0.1:1234")
	remoteAddrEntry := widget.NewEntry()
	remoteAddrEntry.SetPlaceHolder("123.123.123.123:22")
	forwardTypeSelect := widget.NewSelect([]string{"Local", "Remote", "Dynamic (SOCKS)"}, nil)
	forwardTypeSelect.SetSelected("Local")
	useProxyCheck := widget.NewCheck("Use HTTP Proxy", nil)
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
		{Text: "Key Passphrase:", Widget: keyPassEntry},
		{Text: "", Widget: use2FACheck},
		{Text: "Forward Type:", Widget: forwardTypeSelect},
		{Text: "Local Address:", Widget: localAddrEntry},
		{Text: "Remote Address:", Widget: remoteAddrEntry},
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
				User:          userEntry.Text,
				Password:      passwordEntry.Text,
				KeyPath:       keyPathEntry.Text,
				KeyPassphrase: keyPassEntry.Text,
				Use2FA:        use2FACheck.Checked,
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
	keyPassEntry := widget.NewPasswordEntry()
	keyPassEntry.SetText(cfg.Auth.KeyPassphrase)
	use2FACheck := widget.NewCheck("Enable 2FA", nil)
	use2FACheck.SetChecked(cfg.Auth.Use2FA)
	localAddrEntry := widget.NewEntry()
	remoteAddrEntry := widget.NewEntry()
	forwardTypeSelect := widget.NewSelect([]string{"Local", "Remote", "Dynamic (SOCKS)"}, nil)
	if len(cfg.Forwards) > 0 {
		localAddrEntry.SetText(cfg.Forwards[0].LocalAddr)
		remoteAddrEntry.SetText(cfg.Forwards[0].RemoteAddr)
		forwardTypeSelect.SetSelected(cfg.Forwards[0].Type.String())
	}
	useProxyCheck := widget.NewCheck("Use HTTP Proxy", nil)
	proxyHostEntry := widget.NewEntry()
	proxyHostEntry.SetPlaceHolder("proxy.company.com")
	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText("80")
	proxyUserEntry := widget.NewEntry()
	proxyUserEntry.SetPlaceHolder("proxy_username")
	proxyPassEntry := widget.NewPasswordEntry()
	proxyPassEntry.SetPlaceHolder("proxy_password")
	proxyTLSCheck := widget.NewCheck("HTTPS Proxy", nil)
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
		{Text: "Key Passphrase:", Widget: keyPassEntry},
		{Text: "", Widget: use2FACheck},
		{Text: "Forward Type:", Widget: forwardTypeSelect},
		{Text: "Local Address:", Widget: localAddrEntry},
		{Text: "Remote Address:", Widget: remoteAddrEntry},
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
		state.configs[idx] = TunnelConfig{
			Name:    nameEntry.Text,
			SSHHost: sshHostEntry.Text,
			SSHPort: port,
			Auth: SSHAuthConfig{
				User:          userEntry.Text,
				Password:      passwordEntry.Text,
				KeyPath:       keyPathEntry.Text,
				KeyPassphrase: keyPassEntry.Text,
				Use2FA:        use2FACheck.Checked,
			},
			Proxy: proxy,
			Forwards: []ForwardConfig{{
				Type:       forwardType,
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
	if rt, exists := state.running[idx]; exists {
		rt.stop(state)
		delete(state.running, idx)
	}
	state.configs = append(state.configs[:idx], state.configs[idx+1:]...)
	if state.selectedIdx == idx {
		state.selectedIdx = -1
	} else if state.selectedIdx > idx {
		state.selectedIdx--
	}
	newRunning := make(map[int]*RunningTunnel)
	for i, rt := range state.running {
		if i > idx {
			newRunning[i-1] = rt
		} else if i < idx {
			newRunning[i] = rt
		}
	}
	state.running = newRunning
	if err := saveConfigFile(state.configs, configFile); err != nil {
		log.Printf("Failed to save config: %v", err)
	}
	state.refreshList()
	state.updateStatus()
}
