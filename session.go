package main

import (
	"errors"
	"fmt"
	"github.com/ScriptRock/sftp"
	//"golang.org/x/crypto/ssh"
	"bytes"
	"github.com/ScriptRock/crypto/ssh"
	"github.com/ScriptRock/crypto/ssh/agent"
	"golang.org/x/crypto/openpgp"
	"gopkg.in/gomail.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type FileError struct {
	path string
	err  error
}

type SftpSession struct {
	LocalFiles    map[string]os.FileInfo
	RemoteFiles   map[string]os.FileInfo
	GetFiles      map[string]os.FileInfo
	connection    *ssh.Client
	client        *sftp.Client
	section       *Section
	sshConfig     ssh.ClientConfig
	sshkey        ssh.Signer
	fileregexp    *regexp.Regexp
	decryptEntity *openpgp.Entity
	encryptEntity *openpgp.Entity
	entityList    openpgp.EntityList
}

func NewSftpSession(cfg *Section) (*SftpSession, error) {
	s := SftpSession{
		LocalFiles:  make(map[string]os.FileInfo),
		RemoteFiles: make(map[string]os.FileInfo),
		GetFiles:    make(map[string]os.FileInfo),
		section:     cfg,
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

	addr := fmt.Sprintf("%s:%d", s.section.Server, s.section.Port)
	var err error

	if s.section.ProxyServer != "" {

		paddr := fmt.Sprintf("%s:%d", s.section.ProxyServer, s.section.ProxyPort)
		log.Printf("connect to proxy %s", paddr)
		conn, err := net.Dial("tcp", paddr)
		if err != nil {
			return err
		}

		// http connect
		connstr := []byte("CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n")
		if _, err := conn.Write(connstr); err != nil {
			return errors.New("failed to write connect to http proxy at " + paddr + ": " + err.Error())
		}
		buf := make([]byte, 100)
		respok := []byte(" 200 ")
		if _, err := io.ReadFull(conn, buf); err != nil {
			return errors.New("failed to read response from http proxy at " + paddr + ": " + err.Error())
		}
		if !bytes.Contains(buf, respok) {
			return errors.New("error response from http proxy at " + paddr + ": " + string(buf))
		}

		// CONNECT www.google.com.au:443 HTTP/1.1
		// Host: www.google.com.au:443
		//
		// HTTP/1.0 200 Connection Established
		// Proxy-agent: Apache

		sshconn, inch, inrq, err := ssh.NewClientConn(conn, paddr, &s.sshConfig)
		if err != nil {
			return err
		}
		s.connection = ssh.NewClient(sshconn, inch, inrq)

	} else {
		log.Printf("connect to %s", addr)
		s.connection, err = ssh.Dial("tcp", addr, &s.sshConfig)
		if err != nil {
			return err
		}
	}

	// start sftp
	s.client, err = sftp.NewClient(s.connection)
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

	err := os.Remove(s.section.LockDir)
	if err != nil {
		return fmt.Errorf("unable to remove lock directory, %s", err)
	}
	log.Printf("end %s\n", profile)

	return nil
}

func (s *SftpSession) initSftpSession() error {

	var err error
	s.fileregexp, err = regexp.Compile(s.section.MatchRegExp)
	if err != nil {
		return err
	}

	if s.section.LogFile != "" {
		err = s.setLog(s.section.LogFile)
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
	if s.section.Key != "" {
		err := s.getKeyFile(s.section.Key)
		if err != nil {
			return fmt.Errorf("error : cannot read ssh key file %s, %s", s.section.Key, err)
		} else {
			//auths = append(auths, ssh.PublicKeys(s.sshkeychain))
			//auths = append(auths, ssh.PublicKeys(s.sshkey))
			auths = []ssh.AuthMethod{ssh.PublicKeys(s.sshkey)}
		}
	}
	// add a password if set
	if s.section.Password != "" {
		auths = append(auths, ssh.Password(s.section.Password))
	}

	// configure ssh
	sshCommonConfig := ssh.Config{}
	if s.section.InsecureCiphers {
		sshCommonConfig = ssh.Config{Ciphers: ssh.AllSupportedCiphers()}
		if debug {
			log.Printf("DEBUG insecureciphers is set : using weaker ciphers.\n")
		}
	}
	sshCommonConfig.SetDefaults()

	s.sshConfig = ssh.ClientConfig{
		User:   s.section.Username,
		Auth:   auths,
		Config: sshCommonConfig,
	}

	// test for local directory
	if _, err := os.Stat(s.section.LocalDir); err != nil {
		if os.IsNotExist(err) {
			// file does not exist
			return fmt.Errorf("error : local directory does not exist : %s", s.section.LocalDir)
		}
	}

	if archive {
		// test for archive directory
		if _, err := os.Stat(s.section.ArchiveDir); err != nil {
			if os.IsNotExist(err) {
				// file does not exist
				return fmt.Errorf("error : archive directory does not exist : %s", s.section.ArchiveDir)
			}
		}
	}

	// grab lock directory
	if debug {
		log.Printf("DEBUG mklockdir: %s\n", s.section.LockDir)
	}
	err = os.Mkdir(s.section.LockDir, 0700)
	if err != nil {
		return fmt.Errorf("mkLockDir error : %s", err)
	}

	// check pgp gumpf
	if s.section.Encrypt {

		// open public keyring
		kr, err := os.Open(s.section.PublicKeyRing)
		if err != nil {
			return fmt.Errorf("open public keyring error: %s\n", err.Error())
		}
		defer kr.Close()

		// read public keyring
		eList, err := openpgp.ReadKeyRing(kr)
		if err != nil {
			return fmt.Errorf("read public keyring error: %s\n", err.Error())
		}
		// look for public key
		s.encryptEntity = s.getKeyByIdShortString(eList, s.section.EncryptKeyId)
		if s.encryptEntity == nil {
			return fmt.Errorf("cannot find encryption key with ID : %s\n", s.section.EncryptKeyId)
		}

	}

	if s.section.Decrypt {

		// Open the private key file
		kr, err := os.Open(s.section.PrivateKeyRing)
		if err != nil {
			return err
		}
		defer kr.Close()
		s.entityList, err = openpgp.ReadKeyRing(kr)
		if err != nil {
			return err
		}

		s.decryptEntity = s.getKeyByIdShortString(s.entityList, s.section.DecryptKeyId)
		if s.decryptEntity == nil {
			return fmt.Errorf("cannot find decryption key with ID : %s\n", s.section.DecryptKeyId)
		}

		// Get the passphrase and read the private key.
		passphrase := []byte(s.section.DecryptPassphrase)
		s.decryptEntity.PrivateKey.Decrypt(passphrase)
		for _, subkey := range s.decryptEntity.Subkeys {
			subkey.PrivateKey.Decrypt(passphrase)
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
	walker := s.client.Walk(s.section.RemoteDir)
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
			rel, _ := filepath.Rel(s.section.RemoteDir, p)
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

func (s *SftpSession) GetRemoteSize(rpath string) (int64, error) {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return 0, err
		}
	}

	rstat, err := s.client.Stat(rpath)
	if err != nil {
		return 0, err
	}

	return rstat.Size(), nil

}

func (s *SftpSession) MkDirRemote(rdir string, rmode os.FileMode) error {
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
	err = s.client.Chmod(rdir, rmode)
	if err != nil {
		// ignore chmod errors for now - just log it
		log.Printf("warning: error setting mode on remote dir: %s %s", rdir, err.Error())
	}
	return nil
}

func (s *SftpSession) RemoveRemote(rname string) error {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}

	err := s.client.Remove(rname)
	if err != nil {
		return err
	}

	return nil
}

func (s *SftpSession) Push(lfile string, rfile string, size int64, rmode os.FileMode) error {

	if s.client == nil {
		err := s.Connect()
		if err != nil {
			return err
		}
	}

	// it's a file on remote host
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
		return fmt.Errorf("copy error: expected %v bytes, copied %d bytes", size, n)
	}
	log.Printf("wrote %v bytes in %s", size, time.Since(t1))

	err = w.Chmod(rmode)
	if err != nil {
		return err
	}

	return nil
}

func (s *SftpSession) Pull(rfile string, lfile string, size int64, mode os.FileMode) error {

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
		return fmt.Errorf("pull file %s : expected %v bytes, got %d", rfile, size, n)
	}
	log.Printf("pull file %s, %v bytes in %s", rfile, size, time.Since(t1))

	err = w.Chmod(mode)
	if err != nil {
		return err
	}
	return nil
}

func (s *SftpSession) getKeyFile(fkey string) error {
	buf, err := ioutil.ReadFile(fkey)
	if err != nil {
		return err
	}
	s.sshkey, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return err
	}
	return nil
}

func (s *SftpSession) EncryptFile(fname string) (string, os.FileInfo, error) {

	// encrypted file
	lfile := fname + s.section.EncryptSuffix
	lw, err := os.Create(lfile)
	if err != nil {
		return "", nil, err
	}
	defer lw.Close()

	w, err := openpgp.Encrypt(lw, []*openpgp.Entity{s.encryptEntity}, nil, nil, nil)
	if err != nil {
		return "", nil, err
	}

	file2encrypt, err := os.Open(fname)
	if err != nil {
		return "", nil, err
	}

	_, err = io.Copy(w, file2encrypt)
	if err != nil {
		return "", nil, err
	}

	err = w.Close()
	if err != nil {
		return "", nil, err
	}

	lstat, err := os.Stat(lfile)
	if err != nil {
		return "", nil, err
	}

	return lfile, lstat, nil
}

func (s *SftpSession) DecryptFile(fname string) (string, error) {

	lr, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer lr.Close()

	fdecrypted := strings.TrimSuffix(fname, filepath.Ext(fname))

	lw, err := os.Create(fdecrypted)
	if err != nil {
		return "", fmt.Errorf("open file error: %s, %s\n", fdecrypted, err.Error())
	}

	// Decrypt it with the contents of the private key
	msg, err := openpgp.ReadMessage(lr, s.entityList, nil, nil)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(lw, msg.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return fdecrypted, nil
}

func (s *SftpSession) getKeyByIdShortString(keyring openpgp.EntityList, keyidstr string) *openpgp.Entity {
	for _, entity := range keyring {
		//kid := entity.PrimaryKey.KeyId
		kid := entity.PrimaryKey.KeyIdShortString()
		if kid == keyidstr {
			return entity
		}
	}
	return nil
}

func (s *SftpSession) CopyFile(src string, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}

// called from main to allow session to check whether an email is worthy or not
func (s *SftpSession) TriggerEmail(e error) error {

	log.Printf("trigger email\n")
	if !s.section.EmailSuccess && !s.section.EmailFailure {
		log.Printf("trigger no email\n")
		return nil
	}
	if e != nil && !s.section.EmailFailure {
		log.Printf("trigger email on failure\n")
		return nil
	}
	if e == nil && !s.section.EmailSuccess {
		log.Printf("trigger email on success\n")
		return nil
	}

	if s.section.LogFile == "" {
		// do nothing if no log is in use
		return nil
	}
	log.Printf("trigger email coming\n")

	var body []byte
	body, err := ioutil.ReadFile(s.section.LogFile)
	if err != nil {
		return err
	}

	m := gomail.NewMessage()
	var subject string
	if e != nil {
		subject = "sftpsyncr " + profile + " failure"
	} else {
		subject = "sftpsyncr " + profile + " success"
	}
	m.SetHeader("From", s.section.EmailFrom)
	m.SetHeader("To", s.section.EmailTo)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", string(body))

	d := gomail.Dialer{Host: s.section.EmailHost, Port: s.section.EmailPort}
	err = d.DialAndSend(m)
	if err != nil {
		log.Printf("email send failed: %s\n", err)
		return err
	}
	return nil

}
