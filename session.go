package main

import (
	"errors"
	"fmt"
	"github.com/ScriptRock/sftp"
	//"golang.org/x/crypto/ssh"
	"github.com/ScriptRock/crypto/ssh"
	"github.com/ScriptRock/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type SftpSession struct {
	LocalFiles  map[string]os.FileInfo
	RemoteFiles map[string]os.FileInfo
	connection  *ssh.Client
	client      *sftp.Client
	config      *Config
	section     string
	insecure    bool
	sshConfig   ssh.ClientConfig
	fileregexp  *regexp.Regexp
}

func NewSftpSession(cfg *Config, pname string) (*SftpSession, error) {
	s := SftpSession{
		LocalFiles:  make(map[string]os.FileInfo),
		RemoteFiles: make(map[string]os.FileInfo),
		config:      cfg,
		section:     pname,
		insecure:    false,
		connection:  nil,
		client:      nil,
	}
	// test all configurables
	err := s.initSftpSession()
	if err != nil {
		return nil, err
	}

	// ready to start
	log.Printf("start %s\n", profile)

	return &s, nil
}

func (s *SftpSession) Connect() error {

	addr := fmt.Sprintf("%s:%d", s.config.Profile[profile].Server, s.config.Profile[profile].Port)
	log.Printf("connect to %s", addr)
	connection, err := ssh.Dial("tcp", addr, &s.sshConfig)
	if err != nil {
		return err
	}

	// start sftp
	s.client, err = sftp.NewClient(connection)
	if err != nil {
		return fmt.Errorf("unable to start sftp subsytem: %v", err)
	}

	return nil

}

func (s *SftpSession) Close() error {
	if s.connection != nil {
		s.connection.Close()
	}
	if s.client != nil {
		s.client.Close()
	}

	err := os.Remove(s.config.Profile[profile].LockDir)
	if err != nil {
		return fmt.Errorf("unable to remove lock directory, %s", err)
	}
	log.Printf("end %s\n", profile)

	return nil
}

func (s *SftpSession) initSftpSession() error {

	if s.config.Profile[profile].Server == "" {
		return errors.New("required profile configurable server not set")
	}
	if s.config.Profile[profile].Username == "" {
		return errors.New("required profile configurable username not set")
	}
	if s.config.Profile[profile].Password == "" && s.config.Profile[profile].Key == "" {
		if len(os.Getenv("SSH_AUTH_SOCK")) == 0 {
			return errors.New("set an auth method using an ssh-agent and SSH_AUTH_SOCK env, or by setting a key or a password in the config file.")
		}
	}
	if s.config.Profile[profile].Port == 0 {
		s.config.Profile[profile].Port = config.Defaults.Port
	}
	if s.config.Profile[profile].MatchRegExp == "" {
		s.config.Profile[profile].MatchRegExp = config.Defaults.MatchRegExp
	}
	if s.config.Profile[profile].LocalDir == "" {
		return errors.New("required profile configurable localdir not set")
	}
	if s.config.Profile[profile].RemoteDir == "" {
		return errors.New("required profile configurable remotedir not set")
	}
	if s.config.Profile[profile].LogFile == "" {
		if config.Defaults.LogFile != "" {
			s.config.Profile[profile].LogFile = config.Defaults.LogFile
		}
	}
	if s.config.Profile[profile].LockDir == "" {
		s.config.Profile[profile].LockDir = config.Defaults.LockDir
	}
	if s.config.Profile[profile].Debug {
		debug = s.config.Profile[profile].Debug
	}
	if config.Defaults.InsecureCiphers {
		s.insecure = config.Defaults.InsecureCiphers
	}
	if s.config.Profile[profile].InsecureCiphers {
		s.insecure = s.config.Profile[profile].InsecureCiphers
	}

	var err error
	s.fileregexp, err = regexp.Compile(s.config.Profile[profile].MatchRegExp)
	if err != nil {
		return err
	}

	if s.config.Profile[profile].LogFile != "" {
		err = s.setLog(s.config.Profile[profile].LogFile)
		if err != nil {
			return err
		}
	}

	// set ssh auth methods
	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}
	// if key is set, add to allowed auths
	if s.config.Profile[profile].Key != "" {
		key, err := s.getKeyFile(s.config.Profile[profile].Key)
		if err != nil {
			return fmt.Errorf("error : cannot read ssh key file %s, %s", s.config.Profile[profile].Key, err)
		} else {
			auths = append(auths, ssh.PublicKeys(key))
		}
	}
	// add a password if set
	if s.config.Profile[profile].Password != "" {
		auths = append(auths, ssh.Password(s.config.Profile[profile].Password))
	}

	// configure ssh
	/*
		defaultPlusDiscouragedCiphers := []string{
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			"aes128-gcm@openssh.com",
			"arcfour256", "arcfour128",
			"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
		}
	*/

	sshCommonConfig := ssh.Config{}
	if s.insecure {
		sshCommonConfig = ssh.Config{Ciphers: ssh.AllSupportedCiphers()}
	}
	sshCommonConfig.SetDefaults()

	s.sshConfig = ssh.ClientConfig{
		User:   s.config.Profile[profile].Username,
		Auth:   auths,
		Config: sshCommonConfig,
	}

	// grab lock directory
	if s.config.Profile[profile].LockDir == "" {
		return errors.New("error : required configurable lockdir is not set.")
	}
	if debug {
		log.Printf("DEBUG mklockdir: %s\n", s.config.Profile[profile].LockDir)
	}
	err = os.Mkdir(s.config.Profile[profile].LockDir, 022)
	if err != nil {
		return fmt.Errorf("mkLockDir error : %s", err)
	}

	// test for local directory
	if _, err := os.Stat(s.config.Profile[profile].LocalDir); err != nil {
		if os.IsNotExist(err) {
			// file does not exist
			return fmt.Errorf("error : local directory does not exist : %s", s.config.Profile[profile].LocalDir)
		}
	}

	return nil

}

func (s *SftpSession) setLog(file string) error {

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

func (s *SftpSession) WalkLocal(path string, f os.FileInfo, err error) error {

	rel, err := filepath.Rel(config.Profile[profile].LocalDir, path)
	if err != nil {
		return err
	}
	if debug {
		log.Printf("DEBUG relative local file %s with %d bytes\n", rel, f.Size())
	}
	// only add the file if it matches the regexp
	if matched := s.fileregexp.MatchString(f.Name()); matched {
		s.LocalFiles[rel] = f
	}
	return nil
}

func (s *SftpSession) WalkRemote() error {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}
	if debug {
		log.Printf("DEBUG remote dir: %s\n", s.config.Profile[profile].RemoteDir)
	}
	walker := s.client.Walk(s.config.Profile[profile].RemoteDir)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			log.Println(err)
			continue
		}
		rstat := walker.Stat()

		if debug {
			log.Printf("DEBUG remote path: %s,\tsize: %d", walker.Path(), rstat.Size())
		}

		// only add the file to the list if it matches regexp
		if matched := s.fileregexp.MatchString(rstat.Name()); matched {
			p := walker.Path()
			rel, _ := filepath.Rel(s.config.Profile[profile].RemoteDir, p)
			s.RemoteFiles[rel] = rstat
		}

		//              log.Println(walker.Path())
		//    Name() string       // base name of the file
		//    Size() int64        // length in bytes for regular files; system-dependent for others
		//    Mode() FileMode     // file mode bits
		//    ModTime() time.Time // modification time
		//    IsDir() bool        // abbreviation for Mode().IsDir()
		//    Sys() interface{}   // underlying data source (can return nil)
	}

	return nil

}

func (s *SftpSession) MkDirRemote(rdir string) error {
	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}
	err := s.client.Mkdir(rdir)
	if err != nil {
		return err
	}
	return nil
}

func (s *SftpSession) Push(lfile string, size int64, rfile string) error {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}
	// open file on remote host
	w, err := s.client.Create(rfile)
	if err != nil {
		return err
	}
	defer w.Close()

	f, err := os.Open(lfile)
	if err != nil {
		return err
	}
	defer f.Close()

	t1 := time.Now()
	n, err := io.Copy(w, io.LimitReader(f, size))
	if err != nil {
		return err
	}
	if n != size {
		log.Fatalf("copy: expected %v bytes, got %d", size, n)
	}
	log.Printf("wrote %v bytes in %s", size, time.Since(t1))

	return nil
}

func (s *SftpSession) Pull(rfile string, size int64, lfile string) error {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}
	// open file on remote host
	r, err := s.client.Open(rfile)
	if err != nil {
		return err
	}
	defer r.Close()

	w, err := os.Create(lfile)
	if err != nil {
		return err
	}
	defer w.Close()

	t1 := time.Now()
	n, err := io.Copy(w, io.LimitReader(r, size))
	if err != nil {
		return err
	}
	if n != size {
		log.Fatalf("pull copy: expected %v bytes, got %d", size, n)
	}
	log.Printf("pull wrote %v bytes in %s", size, time.Since(t1))

	return nil
}

func (s *SftpSession) getKeyFile(fkey string) (key ssh.Signer, err error) {
	buf, err := ioutil.ReadFile(fkey)
	if err != nil {
		return nil, err
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
