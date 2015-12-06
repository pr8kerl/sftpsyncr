package main

import (
	//	"errors"
	"gopkg.in/gcfg.v1"
	"log"
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
	InsecureCiphers bool
	Debug           bool
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
	//	if config.Defaults.LogFile == "" {
	//		err = errors.New("required defaults configurable logfile not set")
	//		return err
	//	}
	if config.Defaults.LockDir == "" {
		config.Defaults.LockDir = "./sftpsyncr.lock"
		log.Printf("setting default lockdir to ./sftpsyncr.lock")
	}
	if config.Defaults.Debug {
		debug = config.Defaults.Debug
	}

	return nil

}
