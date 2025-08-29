package main

import (
	"encoding/json"
	"os"
	"sync"

	"fyne.io/fyne/v2/widget"
)

type ForwardType int

const (
	ForwardLocal ForwardType = iota
	ForwardRemote
	ForwardDynamic
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
	LocalAddr  string      `json:"local_addr"`
	RemoteAddr string      `json:"remote_addr"`
}

type ProxyConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"`
}

type SSHAuthConfig struct {
	User          string `json:"user"`
	Password      string `json:"password"`
	KeyPath       string `json:"key_path"`
	KeyPassphrase string `json:"key_passphrase"`
	Use2FA        bool   `json:"use_2fa"`
}

type TunnelConfig struct {
	Name     string          `json:"name"`
	SSHHost  string          `json:"ssh_host"`
	SSHPort  int             `json:"ssh_port"`
	Auth     SSHAuthConfig   `json:"auth"`
	Proxy    *ProxyConfig    `json:"proxy,omitempty"`
	Forwards []ForwardConfig `json:"forwards"`
}

type AppState struct {
	configs      []TunnelConfig
	running      map[int]*RunningTunnel
	list         *widget.List
	status       *widget.Label
	selectedIdx  int
	connections  map[string]*sshConnection
	connMu       sync.Mutex
}

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
		return []TunnelConfig{}, nil
	}
	var cfgs []TunnelConfig
	err = json.Unmarshal(data, &cfgs)
	return cfgs, err
}