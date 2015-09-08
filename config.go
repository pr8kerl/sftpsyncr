package main

import (
	"errors"
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
		Port        uint32
		MatchRegExp string
		LogFile     string
		LockDir     string
		Debug       bool
	}
	Profile map[string]*Section
}

type Section struct {
	Server      string
	Username    string
	Password    string
	Key         string
	Port        uint32
	MatchRegExp string
	LocalDir    string
	RemoteDir   string
	LogFile     string
	LockDir     string
	Debug       bool
}

func InitialiseConfig(file string) error {

	err := gcfg.ReadFileInto(&config, file)
	if err != nil {
		return err
	}
	if config.Defaults.Port == 0 {
		config.Defaults.Port = 22
	}
	if config.Defaults.MatchRegExp == "" {
		config.Defaults.MatchRegExp = ".*"
	}
	if config.Defaults.LogFile == "" {
		err = errors.New("required defaults configurable logfile not set")
		return err
	}
	if config.Defaults.LockDir == "" {
		config.Defaults.LockDir = "./sftpsyncr.lock"
		log.Printf("setting default lockdir to ./sftpsyncr.lock")
	}
	if config.Defaults.Debug {
		debug = config.Defaults.Debug
	}

	if config.Profile[profile].Server == "" {
		err = errors.New("required profile configurable server not set")
		return err
	}
	if config.Profile[profile].Username == "" {
		err = errors.New("required profile configurable username not set")
		return err
	}
	if config.Profile[profile].Password == "" && config.Profile[profile].Key == "" {
		agent := os.Getenv("SSH_AUTH_SOCK")
		if agent == "" {
			err = errors.New("set an auth method using an ssh-agent and SSH_AUTH_SOCK env, or by setting a key or a password in the config file.")
			return err
		}
	}
	if config.Profile[profile].Port == 0 {
		config.Profile[profile].Port = config.Defaults.Port
	}
	if config.Profile[profile].MatchRegExp == "" {
		config.Profile[profile].MatchRegExp = config.Defaults.MatchRegExp
	}
	if config.Profile[profile].LocalDir == "" {
		err = errors.New("required profile configurable localdir not set")
		return err
	}
	if config.Profile[profile].RemoteDir == "" {
		err = errors.New("required profile configurable remotedir not set")
		return err
	}
	if config.Profile[profile].LogFile == "" {
		config.Profile[profile].LogFile = config.Defaults.LogFile
	}
	if config.Profile[profile].LockDir == "" {
		config.Profile[profile].LockDir = config.Defaults.LockDir
	}
	if config.Profile[profile].Debug {
		debug = config.Profile[profile].Debug
	}

	fileregexp, err = regexp.Compile(config.Profile[profile].MatchRegExp)
	if err != nil {
		return err
	}

	err = setLog(config.Profile[profile].LogFile)
	if err != nil {
		return err
	}

	return nil

}

func setLog(file string) error {

	lf, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	log.SetOutput(lf)
	if debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}
	log.SetPrefix(profile + " : ")

	return nil

}
