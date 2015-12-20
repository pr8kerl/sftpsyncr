package main

import (
	//	"errors"
	"errors"
	"fmt"
	"gopkg.in/gcfg.v1"
	"log"
	"os"
	"regexp"
)

var (
	config     Config
	debug      bool = false
	fileregexp *regexp.Regexp
)

type Config struct {
	Defaults struct {
		Port            uint32
		MatchRegExp     string
		LogFile         string
		LockDir         string
		ProxyServer     string
		ProxyPort       uint32
		InsecureCiphers bool
		Debug           bool
	}
	Profile map[string]*Section
}

type Section struct {
	Server          string
	Username        string
	Password        string
	Key             string
	Port            uint32
	MatchRegExp     string
	LocalDir        string
	RemoteDir       string
	LogFile         string
	LockDir         string
	ProxyServer     string
	ProxyPort       uint32
	InsecureCiphers bool
	Debug           bool
}

func InitialiseConfig(file string) (*Section, error) {

	var sectn = Section{}
	err := gcfg.ReadFileInto(&config, file)
	if err != nil {
		return nil, err
	}

	if config.Defaults.Port == 0 {
		config.Defaults.Port = 22
	}
	if config.Defaults.Port < 1 || config.Defaults.Port > 0xffff {
		return nil, fmt.Errorf("port number out of range: %d", config.Defaults.Port)
	}
	if config.Defaults.MatchRegExp == "" {
		config.Defaults.MatchRegExp = ".*"
	}
	if config.Defaults.LockDir == "" {
		config.Defaults.LockDir = "./sftpsyncr.lock"
		log.Printf("setting default lockdir to ./sftpsyncr.lock")
	}
	if config.Defaults.Debug {
		debug = config.Defaults.Debug
	}
	if config.Profile[profile].Server == "" {
		return nil, errors.New("required profile configurable server not set")
	}
	sectn.Server = config.Profile[profile].Server

	if config.Profile[profile].Port == 0 {
		sectn.Port = config.Defaults.Port
	} else {
		sectn.Port = config.Profile[profile].Port
	}
	if sectn.Port < 1 || sectn.Port > 0xffff {
		return nil, fmt.Errorf("profile port number out of range: %d", sectn.Port)
	}

	if config.Profile[profile].Username == "" {
		return nil, errors.New("required profile configurable username not set")
	}
	sectn.Username = config.Profile[profile].Username

	if config.Profile[profile].Password == "" && config.Profile[profile].Key == "" {
		if len(os.Getenv("SSH_AUTH_SOCK")) == 0 {
			return nil, errors.New("set an auth method using an ssh-agent and SSH_AUTH_SOCK env, or by setting a key or a password in the config file.")
		}
	}
	sectn.Password = config.Profile[profile].Password
	sectn.Key = config.Profile[profile].Key

	if config.Profile[profile].MatchRegExp == "" {
		sectn.MatchRegExp = config.Defaults.MatchRegExp
	}

	if config.Profile[profile].LocalDir == "" {
		return nil, errors.New("required profile configurable localdir not set")
	}
	sectn.LocalDir = config.Profile[profile].LocalDir

	if config.Profile[profile].RemoteDir == "" {
		return nil, errors.New("required profile configurable remotedir not set")
	}
	sectn.RemoteDir = config.Profile[profile].RemoteDir

	if config.Profile[profile].LogFile == "" {
		if config.Defaults.LogFile != "" {
			sectn.LogFile = config.Defaults.LogFile
		}
	} else {
		sectn.LogFile = config.Profile[profile].LogFile
	}

	if config.Profile[profile].LockDir == "" {
		sectn.LockDir = config.Defaults.LockDir
	} else {
		sectn.LockDir = config.Profile[profile].LockDir
	}

	if config.Defaults.ProxyServer != "" && config.Defaults.ProxyPort == 0 {
		return nil, errors.New("required configurable proxyport not set")
	}
	if config.Defaults.ProxyServer != "" {
		if config.Profile[profile].ProxyServer == "" {
			sectn.ProxyServer = config.Defaults.ProxyServer
			sectn.ProxyPort = config.Defaults.ProxyPort
		}
	}
	if config.Profile[profile].ProxyServer != "" && config.Profile[profile].ProxyPort == 0 {
		return nil, errors.New("required profile configurable proxyport not set")
	}
	if config.Profile[profile].ProxyServer != "" {
		sectn.ProxyServer = config.Profile[profile].ProxyServer
		sectn.ProxyPort = config.Profile[profile].ProxyPort
		if sectn.ProxyPort < 1 || sectn.ProxyPort > 0xffff {
			return nil, fmt.Errorf("profile proxy port number out of range: %d", sectn.ProxyPort)
		}
	}

	if config.Profile[profile].Debug {
		debug = config.Profile[profile].Debug
	}

	if config.Defaults.InsecureCiphers {
		sectn.InsecureCiphers = config.Defaults.InsecureCiphers
	}
	if config.Profile[profile].InsecureCiphers {
		sectn.InsecureCiphers = config.Profile[profile].InsecureCiphers
	}

	return &sectn, nil

}
