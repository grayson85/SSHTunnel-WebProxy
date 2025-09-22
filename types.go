package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	
	"golang.org/x/crypto/ssh"
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

type TunnelStatus int

const (
	StatusStopped TunnelStatus = iota
	StatusConnecting
	StatusConnected
	StatusError
	StatusDisconnected
)

func (s TunnelStatus) String() string {
	switch s {
	case StatusStopped:
		return "Stopped"
	case StatusConnecting:
		return "Connecting"
	case StatusConnected:
		return "Connected"
	case StatusError:
		return "Error"
	case StatusDisconnected:
		return "Disconnected"
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

type RunningTunnel struct {
	Cfg           TunnelConfig
	Status        TunnelStatus
	ErrorMsg      string
	LastHeartbeat time.Time
	Client        *ssh.Client
	closers       []io.Closer
	wg            sync.WaitGroup
	mu            sync.Mutex
	stopping      bool
	stopped       chan struct{}
}

type sshConnection struct {
	client   *ssh.Client
	mu       sync.Mutex
	refCount int
}

type AppState struct {
	configs      []TunnelConfig
	running      map[int]*RunningTunnel
	list         *widget.List
	status       *widget.Label
	selectedIdx  int
	connections  map[string]*sshConnection
	connMu       sync.Mutex
	statusTicker *time.Ticker
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
		// If file doesn't exist, try to find and migrate from old locations
		if os.IsNotExist(err) {
			log.Printf("Config file %s not found, checking for existing configs to migrate", file)
			return migrateConfigFromOldLocations(file)
		}
		return []TunnelConfig{}, err
	}
	var cfgs []TunnelConfig
	err = json.Unmarshal(data, &cfgs)
	if err != nil {
		log.Printf("Error parsing config file: %v", err)
		return []TunnelConfig{}, err
	}
	log.Printf("Loaded %d tunnel configurations from %s", len(cfgs), file)
	return cfgs, err
}

func migrateConfigFromOldLocations(newPath string) ([]TunnelConfig, error) {
	// Try to find config in old locations
	oldLocations := []string{
		"tunnels.json", // Current directory
	}
	
	// Add home directory
	if homeDir, err := os.UserHomeDir(); err == nil {
		oldLocations = append(oldLocations, filepath.Join(homeDir, "tunnels.json"))
	}
	
	// Add executable directory
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		oldLocations = append(oldLocations, filepath.Join(execDir, "tunnels.json"))
	}
	
	for _, oldPath := range oldLocations {
		if data, err := os.ReadFile(oldPath); err == nil {
			log.Printf("Found existing config at %s, migrating to %s", oldPath, newPath)
			
			var cfgs []TunnelConfig
			if err := json.Unmarshal(data, &cfgs); err == nil {
				// Save to new location
				if saveErr := saveConfigFile(cfgs, newPath); saveErr == nil {
					log.Printf("Successfully migrated %d configurations to %s", len(cfgs), newPath)
					return cfgs, nil
				} else {
					log.Printf("Failed to save migrated config: %v", saveErr)
				}
			} else {
				log.Printf("Failed to parse old config file %s: %v", oldPath, err)
			}
		}
	}
	
	log.Printf("No existing config found, starting with empty configuration")
	return []TunnelConfig{}, nil
}
