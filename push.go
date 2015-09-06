package main

import (
	"flag"
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/gcfg.v1"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
)

var (
	fileregexp *regexp.Regexp
)

type PushCommand struct {
	Ui         cli.Ui
	LocalFiles map[string]os.FileInfo
}

func pushCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	return &PushCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
	}, nil
}

func (c *PushCommand) Run(args []string) int {

	var cfgfile string
	cmdFlags := flag.NewFlagSet("instances", flag.ContinueOnError)
	cmdFlags.StringVar(&profile, "profile", "default", "sftp session profile to use")
	cmdFlags.StringVar(&cfgfile, "config", "config.ini", "config file in git config ini format")
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }

	err := gcfg.ReadFileInto(&config, cfgfile)
	if err != nil {
		log.Fatalf("Failed to read config file: %s", err)
	}
	debug = config.Debug
	fileregexp, err = regexp.Compile(config.Profiles[profile].MatchRegExp)
	if err != nil {
		log.Fatalf("failed to compile regular expression : %s", config.Profiles[profile].MatchRegExp)
	}

	// grab lock directory
	if config.LockDir == "" {
		log.Printf("error : required configurable lockdir is not set.")
		return 99
	}
	log.Printf("mklockdir: %s\n", config.LockDir)
	err = os.Mkdir(config.LockDir, 022)
	if err != nil {
		log.Fatalf("error : %s\n", err)
	}
	defer rmLock(config.LockDir)

	// test for local src directory
	if _, err := os.Stat(config.Profiles[profile].LocalDir); err != nil {
		if os.IsNotExist(err) {
			// file does not exist
			log.Printf("error : dest directory does not exist, %s", config.Profiles[profile].LocalDir)
			return 98
		}
	}

	// walk local dir and build file list
	c.LocalFiles = make(map[string]os.FileInfo)
	ldir := config.Profiles[profile].LocalDir
	if ldir == "" {
		log.Fatalln("required configurable localdir is not set for profile %s.", profile)
	}
	filepath.Walk(ldir, c.Walklocal)

	// if file list connect
	if len(c.LocalFiles) > 0 {

		// connect and test remote path
		// defer connect handle close

		var auths []ssh.AuthMethod
		if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
		}
		if config.Profiles[profile].Key != "" {
			key, err := getKeyFile()
			if err != nil {
				log.Fatalln("error : cannot read ssh key file %s, %s", config.Profiles[profile].Key, err)
			} else {
				auths = append(auths, ssh.PublicKeys(key))
			}
		}
		if config.Profiles[profile].Password != "" {
			auths = append(auths, ssh.Password(config.Profiles[profile].Password))
		}

		sshconfig := ssh.ClientConfig{
			User: config.Profiles[profile].Username,
			Auth: auths,
		}
		addr := fmt.Sprintf("%s:%d", config.Profiles[profile].Server, config.Profiles[profile].Port)
		conn, err := ssh.Dial("tcp", addr, &sshconfig)
		if err != nil {
			log.Fatalf("unable to connect to [%s]: %v", addr, err)
			return 97
		}
		defer conn.Close()

		client, err := sftp.NewClient(conn)
		if err != nil {
			log.Fatalf("unable to start sftp subsytem: %v", err)
			return 96
		}
		defer client.Close()

		// foreach filelist send
		for path := range c.LocalFiles {
			rfile := c.LocalFiles[path].Name()
			lsize := c.LocalFiles[path].Size()
			err := send(client, path, lsize, rfile)
			if err != nil {
				log.Printf("error sending file path: %s\n", err)
			}
		}
	} else {
		log.Println("nothing to push")
	}

	return 0

}

func (c *PushCommand) Help() string {
	return "help: push files to a remote sftp server"
}

func (c *PushCommand) Synopsis() string {
	return "synopsis: push files to a remote sftp server"
}

func (c *PushCommand) Walklocal(path string, f os.FileInfo, err error) error {
	if config.Debug {
		log.Printf("DEBUG local file %s with %d bytes\n", path, f.Size())
	}
	c.LocalFiles[path] = f
	return nil
}

func rmLock(ldir string) error {
	err := os.Remove(ldir)
	if err != nil {
		log.Fatalf("unable to remove lock directory, %s\n", err)
	}
	log.Printf("rmlockdir: %s\n", ldir)
	return err
}

func getKeyFile() (key ssh.Signer, err error) {
	file := config.Profiles[profile].Key
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
