package main

import (
	"fmt"
	"log"
	"strconv"

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

	// List
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
			if i >= len(state.configs) {
				return
			}
			cfg := state.configs[i]
			row := o.(*fyne.Container)
			dotContainer := row.Objects[0].(*fyne.Container)
			dot := dotContainer.Objects[0].(*canvas.Circle)
			lbl := row.Objects[1].(*widget.Label)

			if _, running := state.running[i]; running {
				dot.FillColor = theme.SuccessColor()
			} else {
				dot.FillColor = theme.ErrorColor()
			}
			dot.Refresh()
			lbl.SetText(fmt.Sprintf("%s (%s:%d)", cfg.Name, cfg.SSHHost, cfg.SSHPort))
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

	buttons := container.NewHBox(btnAdd, btnEdit, btnDelete, btnStart, btnStop)
	content := container.NewBorder(nil, container.NewVBox(buttons, state.status), nil, nil, state.list)

	w.SetContent(content)
	w.ShowAndRun()
}

func (state *AppState) refreshList() {
	state.list.Refresh()
}

func (state *AppState) updateStatus() {
	status := "Ready"
	if len(state.running) > 0 {
		status = fmt.Sprintf("%d tunnel(s) running", len(state.running))
	}
	state.status.SetText(status)
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
	state.running[idx] = rt
	var twoFACode string
	key := fmt.Sprintf("%s@%s:%d", cfg.Auth.User, cfg.SSHHost, cfg.SSHPort)
	if _, exists := state.connections[key]; !exists && cfg.Auth.Use2FA {
		codeEntry := widget.NewEntry()
		codeEntry.SetPlaceHolder("Enter 2FA code")
		d := dialog.NewForm("2FA Required", "Connect", "Cancel", []*widget.FormItem{
			{Text: "Code:", Widget: codeEntry},
		}, func(confirm bool) {
			if !confirm {
				return
			}
			twoFACode = codeEntry.Text
			if twoFACode == "" {
				dialog.ShowError(fmt.Errorf("2FA code cannot be empty"), w)
				return
			}
			state.status.SetText("Starting tunnel...")
			go func() {
				if err := rt.start(twoFACode, state); err != nil {
					state.status.SetText(fmt.Sprintf("Failed to start tunnel: %v", err))
					return
				}
				state.updateStatus()
				state.refreshList()
			}()
		}, w)
		d.Show()
	} else {
		state.status.SetText("Starting tunnel...")
		go func() {
			if err := rt.start("", state); err != nil {
				state.status.SetText(fmt.Sprintf("Failed to start tunnel: %v", err))
				return
			}
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
	state.status.SetText("Stopping tunnel...")
	rt.stop(state)
	delete(state.running, idx)
	state.updateStatus()
	state.refreshList()
}
