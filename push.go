package main

import (
	"flag"
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
)

type PushCommand struct {
	Ui          cli.Ui
	LocalFiles  map[string]os.FileInfo
	RemoteFiles map[string]os.FileInfo
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

	err := InitialiseConfig(cfgfile)
	if err != nil {
		log.Fatalf("error : failed to initialise config : %s", err)
		return 1
	}

	// grab lock directory
	if config.Profile[profile].LockDir == "" {
		log.Printf("error : required configurable lockdir is not set.")
		return 99
	}
	if debug {
		log.Printf("DEBUG mklockdir: %s\n", config.Profile[profile].LockDir)
	}
	err = os.Mkdir(config.Profile[profile].LockDir, 022)
	if err != nil {
		log.Printf("error : %s\n", err)
		return 66
	}
	defer rmLock(config.Profile[profile].LockDir)

	// test for local src directory
	if _, err := os.Stat(config.Profile[profile].LocalDir); err != nil {
		if os.IsNotExist(err) {
			// file does not exist
			log.Printf("error : local directory does not exist : %s", config.Profile[profile].LocalDir)
			return 98
		}
	}

	// start doing some real work
	log.Printf("start %s\n", profile)
	defer log.Printf("end %s\n", profile)

	// walk local dir and build file list
	c.LocalFiles = make(map[string]os.FileInfo)
	c.RemoteFiles = make(map[string]os.FileInfo)
	ldir := config.Profile[profile].LocalDir
	if ldir == "" {
		log.Fatalln("required configurable localdir is not set for profile %s.", profile)
	}
	filepath.Walk(ldir, c.WalkLocal)

	// if file list connect
	if len(c.LocalFiles) > 0 {

		// connect and test remote path
		// defer connect handle close

		var auths []ssh.AuthMethod
		if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
		}
		if config.Profile[profile].Key != "" {
			key, err := getKeyFile()
			if err != nil {
				log.Fatalln("error : cannot read ssh key file %s, %s", config.Profile[profile].Key, err)
			} else {
				auths = append(auths, ssh.PublicKeys(key))
			}
		}
		if config.Profile[profile].Password != "" {
			auths = append(auths, ssh.Password(config.Profile[profile].Password))
		}

		sshconfig := ssh.ClientConfig{
			User: config.Profile[profile].Username,
			Auth: auths,
		}
		addr := fmt.Sprintf("%s:%d", config.Profile[profile].Server, config.Profile[profile].Port)
		conn, err := ssh.Dial("tcp", addr, &sshconfig)
		if err != nil {
			log.Printf("unable to connect to [%s]: %v", addr, err)
			return 97
		}
		defer conn.Close()

		client, err := sftp.NewClient(conn)
		if err != nil {
			log.Printf("unable to start sftp subsytem: %v", err)
			return 96
		}
		defer client.Close()

		err = walkRemote(client, config.Profile[profile].RemoteDir, &c.RemoteFiles)
		if err != nil {
			log.Printf("unable to walk remote server: %v", err)
			return 95
		}

		// ensure the remote dest directory exists before doing anything
		if _, ok := c.RemoteFiles["."]; ok {
			if debug {
				log.Printf("DEBUG remote directory %s already exists on remote\n", config.Profile[profile].RemoteDir)
			}
		} else {
			err = mkDir(client, config.Profile[profile].RemoteDir)
		}

		// foreach filelist send
		for path := range c.LocalFiles {

			if debug {
				log.Printf("DEBUG processing local path : %s\n", path)
			}

			if _, ok := c.RemoteFiles[path]; ok {
				if debug {
					log.Printf("DEBUG path %s already exists on remote\n", path)
				}
				continue
			} else {
				rfile := filepath.Join(config.Profile[profile].RemoteDir, path)
				lfile := filepath.Join(config.Profile[profile].LocalDir, path)
				lsize := c.LocalFiles[path].Size()
				if c.LocalFiles[path].IsDir() {
					log.Printf("push directory %s\n", rfile)
					mkDir(client, rfile)
				} else {
					log.Printf("push file %s size %d\n", rfile, lsize)
					err := send(client, lfile, lsize, rfile)
					if err != nil {
						log.Printf("error sending file : %s %s\n", path, err)
					}
				}
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

func (c *PushCommand) WalkLocal(path string, f os.FileInfo, err error) error {
	rel, err := filepath.Rel(config.Profile[profile].LocalDir, path)
	if err != nil {
		return err
	}
	if debug {
		log.Printf("DEBUG relative local file %s with %d bytes\n", rel, f.Size())
	}
	// only add the file if it matches the regexp
	if matched := fileregexp.MatchString(f.Name()); matched {
		c.LocalFiles[rel] = f
	}
	return nil
}

func rmLock(ldir string) error {
	err := os.Remove(ldir)
	if err != nil {
		log.Fatalf("unable to remove lock directory, %s\n", err)
	}
	if debug {
		log.Printf("DEBUG rmlockdir: %s\n", ldir)
	}
	return err
}

func getKeyFile() (key ssh.Signer, err error) {
	file := config.Profile[profile].Key
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
