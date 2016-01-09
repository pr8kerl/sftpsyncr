package main

import (
	//	"errors"
	"errors"
	"fmt"
	"gopkg.in/gcfg.v1"
	"log"
	"os"
)

var (
	config      Config
	debug       bool   = false
	stable      bool   = false
	stableblock uint64 = 0
	clean       bool   = false
	archive     bool   = false
)

type Config struct {
	Defaults struct {
		Port              uint32
		MatchRegExp       string
		LogFile           string
		LockDir           string
		ProxyServer       string
		ProxyPort         uint32
		InsecureCiphers   bool
		Debug             bool
		StableSize        bool
		StableDuration    uint64
		Clean             bool
		Archive           bool
		ArchiveDir        string
		PublicKeyRing     string
		PrivateKeyRing    string
		Encrypt           bool
		EncryptKeyId      string
		EncryptRegExp     string
		EncryptSuffix     string
		Decrypt           bool
		DecryptKeyId      []string
		DecryptPassphrase []string
		DecryptRegExp     string
		CleanDecrypted    bool
		Reencrypt         bool
		EmailFailure      bool
		EmailSuccess      bool
		EmailTo           string
		EmailFrom         string
		EmailHost         string
		EmailPort         int
	}
	Profile map[string]*Section
}

type Section struct {
	Server            string
	Username          string
	Password          string
	Key               string
	Port              uint32
	MatchRegExp       string
	LocalDir          string
	RemoteDir         string
	LogFile           string
	LockDir           string
	ProxyServer       string
	ProxyPort         uint32
	InsecureCiphers   bool
	Debug             bool
	StableSize        bool
	StableDuration    uint64
	Clean             bool
	Archive           bool
	ArchiveDir        string
	PublicKeyRing     string
	PrivateKeyRing    string
	Encrypt           bool
	EncryptKeyId      string
	EncryptRegExp     string
	EncryptSuffix     string
	Decrypt           bool
	DecryptKeyId      []string
	DecryptPassphrase []string
	DecryptRegExp     string
	CleanDecrypted    bool
	Reencrypt         bool
	EmailFailure      bool
	EmailSuccess      bool
	EmailTo           string
	EmailFrom         string
	EmailHost         string
	EmailPort         int
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
	if config.Defaults.StableSize {
		stable = config.Defaults.StableSize
	}
	if config.Defaults.StableDuration == 0 {
		config.Defaults.StableDuration = 60
		stableblock = 60
	}
	if config.Defaults.Clean {
		clean = config.Defaults.Clean
	}
	if config.Defaults.Archive {
		archive = config.Defaults.Archive
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
	if config.Profile[profile].StableSize {
		stable = config.Profile[profile].StableSize
	}
	if config.Profile[profile].StableDuration == 0 {
		sectn.StableDuration = config.Defaults.StableDuration
		stableblock = config.Defaults.StableDuration
	} else {
		sectn.StableDuration = config.Profile[profile].StableDuration
		stableblock = config.Profile[profile].StableDuration
	}
	if config.Profile[profile].Clean {
		clean = config.Profile[profile].Clean
	}
	if config.Profile[profile].Archive {
		archive = config.Profile[profile].Archive
	}
	if archive {
		if config.Profile[profile].ArchiveDir == "" {
			if config.Defaults.ArchiveDir == "" {
				return nil, errors.New("if archive is set, profile configurable archivedir is required")
			} else {
				sectn.ArchiveDir = config.Defaults.ArchiveDir
			}
		} else {
			sectn.ArchiveDir = config.Profile[profile].ArchiveDir
		}
	}

	if config.Profile[profile].InsecureCiphers {
		sectn.InsecureCiphers = config.Profile[profile].InsecureCiphers
	}
	if config.Defaults.InsecureCiphers {
		sectn.InsecureCiphers = config.Defaults.InsecureCiphers
	}
	if config.Defaults.EmailHost == "" {
		sectn.EmailHost = "localhost"
	}
	if config.Defaults.EmailPort == 0 {
		sectn.EmailPort = 25
	}
	if config.Profile[profile].EmailHost != "" {
		sectn.EmailHost = config.Profile[profile].EmailHost
	}
	if config.Profile[profile].EmailPort != 0 {
		sectn.EmailPort = config.Profile[profile].EmailPort
	}
	if config.Defaults.EmailSuccess {
		sectn.EmailSuccess = config.Defaults.EmailSuccess
	}
	if config.Profile[profile].EmailSuccess {
		sectn.EmailSuccess = config.Profile[profile].EmailSuccess
	}
	if config.Defaults.EmailFailure {
		sectn.EmailFailure = config.Defaults.EmailFailure
	}
	if config.Profile[profile].EmailFailure {
		sectn.EmailFailure = config.Profile[profile].EmailFailure
	}
	if sectn.EmailSuccess || sectn.EmailFailure {
		if config.Defaults.EmailTo != "" {
			sectn.EmailTo = config.Defaults.EmailTo
		}
		if config.Defaults.EmailFrom != "" {
			sectn.EmailFrom = config.Defaults.EmailFrom
		}
		if config.Profile[profile].EmailTo != "" {
			sectn.EmailTo = config.Profile[profile].EmailTo
		}
		if config.Profile[profile].EmailFrom != "" {
			sectn.EmailFrom = config.Profile[profile].EmailFrom
		}
		if sectn.EmailTo == "" {
			return nil, errors.New("missing emailto configurable.")
		}
		if sectn.EmailFrom == "" {
			return nil, errors.New("missing emailfrom configurable.")
		}
	}

	// PGP settings
	if config.Profile[profile].Decrypt && !sectn.Decrypt {
		sectn.Decrypt = config.Profile[profile].Decrypt
	}
	if config.Profile[profile].Encrypt && !sectn.Encrypt {
		sectn.Encrypt = config.Profile[profile].Encrypt
	}
	if config.Profile[profile].PublicKeyRing != "" && sectn.PublicKeyRing == "" {
		sectn.PublicKeyRing = config.Profile[profile].PublicKeyRing
	}
	if config.Profile[profile].PrivateKeyRing != "" && sectn.PrivateKeyRing == "" {
		sectn.PrivateKeyRing = config.Profile[profile].PrivateKeyRing
	}
	if config.Profile[profile].EncryptKeyId != "" && sectn.EncryptKeyId == "" {
		sectn.EncryptKeyId = config.Profile[profile].EncryptKeyId
	}
	if len(config.Profile[profile].DecryptKeyId) > 0 && len(sectn.DecryptKeyId) == 0 {
		sectn.DecryptKeyId = config.Profile[profile].DecryptKeyId
	}

	if config.Defaults.DecryptRegExp != "" {
		sectn.DecryptRegExp = config.Defaults.DecryptRegExp
	}
	if config.Profile[profile].DecryptRegExp != "" {
		sectn.DecryptRegExp = config.Profile[profile].DecryptRegExp
	}
	if sectn.DecryptRegExp == "" {
		sectn.DecryptRegExp = ".*.gpg$"
	}
	if config.Defaults.EncryptRegExp != "" {
		sectn.EncryptRegExp = config.Defaults.EncryptRegExp
	}
	if config.Profile[profile].EncryptRegExp != "" {
		sectn.EncryptRegExp = config.Profile[profile].EncryptRegExp
	}
	if sectn.EncryptRegExp == "" {
		sectn.EncryptRegExp = ".*"
	}
	if config.Defaults.EncryptSuffix != "" {
		sectn.EncryptSuffix = config.Defaults.EncryptSuffix
	}
	if config.Profile[profile].EncryptSuffix != "" {
		sectn.EncryptSuffix = config.Profile[profile].EncryptSuffix
	}
	if sectn.EncryptSuffix == "" {
		sectn.EncryptSuffix = ".pgp"
	}

	if config.Defaults.CleanDecrypted {
		sectn.CleanDecrypted = config.Defaults.CleanDecrypted
	}
	if config.Profile[profile].CleanDecrypted {
		sectn.CleanDecrypted = config.Profile[profile].CleanDecrypted
	}
	if config.Defaults.Reencrypt {
		sectn.Reencrypt = config.Defaults.Reencrypt
	}
	if config.Profile[profile].Reencrypt {
		sectn.Reencrypt = config.Profile[profile].Reencrypt
	}

	if len(config.Profile[profile].DecryptPassphrase) > 0 && len(sectn.DecryptPassphrase) == 0 {
		sectn.DecryptPassphrase = config.Profile[profile].DecryptPassphrase
	}
	if sectn.Decrypt && sectn.PrivateKeyRing == "" {
		if config.Defaults.PrivateKeyRing != "" {
			sectn.PrivateKeyRing = config.Defaults.PrivateKeyRing
		} else {
			return nil, errors.New("if decrypt is set, privatekeyring must also be set")
		}
	}
	if sectn.Decrypt && len(sectn.DecryptKeyId) == 0 {
		return nil, errors.New("if decrypt is set, decryptkeyid must also be set")
	}
	if sectn.Encrypt && sectn.PublicKeyRing == "" {
		if config.Defaults.PublicKeyRing != "" {
			sectn.PublicKeyRing = config.Defaults.PublicKeyRing
		} else {
			return nil, errors.New("if encrypt is set, publickeyring must also be set")
		}
	}
	if sectn.Encrypt && sectn.EncryptKeyId == "" {
		return nil, errors.New("if encrypt is set, encryptkeyid must also be set")
	}

	return &sectn, nil

}
