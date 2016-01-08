package main

import (
	"flag"
	"github.com/mitchellh/cli"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PushCommand struct {
	Ui   cli.Ui
	good []string
	bad  []FileError
}

func pushCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	// initialise good/bad slices - capacity 128 by default
	fgood := make([]string, 0, 128)
	fbad := make([]FileError, 0, 128)

	return &PushCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
		good: fgood,
		bad:  fbad,
	}, nil
}

func (c *PushCommand) Run(args []string) int {

	// flags
	var cfgfile string
	var err error

	cmdFlags := flag.NewFlagSet("push", flag.ContinueOnError)
	cmdFlags.StringVar(&profile, "profile", "default", "sftp session profile to use")
	cmdFlags.StringVar(&cfgfile, "config", "config.ini", "config file in git config ini format")
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }

	// config
	section, err := InitialiseConfig(cfgfile)
	if err != nil {
		log.Fatalf("error : failed to initialise config : %s", err)
		return 1
	}

	sess, err := NewSftpSession(section)
	if err != nil {
		log.Printf("%s\n", err)
		return 1
	}
	defer sess.Close()

	// run email check at end
	defer sess.TriggerEmail(err)

	// build local file list
	filepath.Walk(config.Profile[profile].LocalDir, sess.WalkLocal)

	// if file list connect
	if len(sess.LocalFiles) > 0 {

		// build remote file list
		err = sess.WalkRemote()
		if err != nil {
			log.Printf("unable to walk remote server: %v", err)
			return 95
		}

		// check remote dest directory
		if _, ok := sess.RemoteFiles["."]; ok {
			if debug {
				log.Printf("DEBUG remote directory %s already exists on remote\n", config.Profile[profile].RemoteDir)
			}
		} else {
			err = sess.MkDirRemote(config.Profile[profile].RemoteDir, 0700)
		}

		// for each local file, if it isn't on remote, send
		for path := range sess.LocalFiles {

			var lsize, rsize int64 = 0, 0

			rfinfo, rexists := sess.RemoteFiles[path]
			lfinfo := sess.LocalFiles[path]

			lsize = lfinfo.Size()
			mode := lfinfo.Mode()

			if debug {
				log.Printf("DEBUG processing local path : %s, %d\n", path, lsize)
			}

			if rexists {
				rsize = rfinfo.Size()
			}

			if lfinfo.IsDir() {

				// prepend the remote dir to the remote file path
				rfile := filepath.Join(config.Profile[profile].RemoteDir, path)

				if !rexists {
					log.Printf("push directory %s\n", rfile)
					sess.MkDirRemote(rfile, mode)
					if err != nil {
						log.Printf("push error creating remote directory : %s, %s\n", rfile, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
						continue
					}
				}

				if archive {

					archivepath := filepath.Join(sess.section.ArchiveDir, path)
					if _, err := os.Stat(archivepath); err != nil {
						if os.IsNotExist(err) {
							// dir does not exist
							err = os.Mkdir(archivepath, mode)
							if err != nil {
								log.Printf("error creating archive directory path : %s, %s\n", archivepath, err)
							}
							if debug {
								log.Printf("DEBUG created archive dir %s\n", archivepath)
							}
						}
					}
				}

				// enough for a directory
				continue

			}

			// ignore if it is on remote
			if rexists && lsize == rsize {

				if debug {
					log.Printf("DEBUG path %s already exists on remote with size %d bytes\n", path, lsize)
				}

				continue

			} else {
				sess.GetFiles[path] = lfinfo
			}

			pcount := len(sess.GetFiles)
			if pcount > 0 {
				log.Printf("found %d local files for upload\n", pcount)
			} else {
				log.Printf("no local files eligible for upload.\n")
				return 0
			}

			// if stable check enabled, wait StableDuration seconds
			if stable {
				log.Printf("stable check enabled - pausing for %d to confirm remote file size stability\n", stableblock)
				time.Sleep(time.Duration(stableblock) * time.Second)
				log.Printf("stable check pause complete.\n")
			}

			for path := range sess.GetFiles {

				var archivepath string

				// if it isn't on remote and it's a different size, send it
				// prepend the remote dir to the remote file path
				rfile := filepath.Join(config.Profile[profile].RemoteDir, path)
				// prepend the local dir to the local file path
				lfilepath := filepath.Join(config.Profile[profile].LocalDir, path)
				lfilesrc := lfilepath
				mode := lfinfo.Mode()

				if sess.section.Encrypt && !strings.HasSuffix(lfilepath, sess.section.EncryptSuffix) {
					lfilepath, lfinfo, err = sess.EncryptFile(lfilepath)
					if err != nil {
						log.Printf("push error encrypting file : %s, %s\n", lfilepath, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
						continue
					}
					lsize = lfinfo.Size()
					log.Printf("push encrypted file: %s\n", lfilepath)
					rfile = rfile + sess.section.EncryptSuffix
				}

				log.Printf("push file %s size %d\n", rfile, lsize)
				err = sess.Push(lfilepath, rfile, lsize, mode)
				if err != nil {
					log.Printf("error pushing file : %s %s\n", path, err)
					c.bad = append(c.bad, FileError{path: path, err: err})
					// bail??
					continue
				}

				if archive {
					archivepath = filepath.Join(sess.section.ArchiveDir, path)
					// copy lfilepath to archivepath
					err = sess.CopyFile(lfilepath, archivepath)
					if err != nil {
						log.Printf("error archiving file : %s %s\n", path, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
						continue
					}
					if debug {
						log.Printf("DEBUG archive file %s\n", archivepath)
					}
				}

				if clean {
					if sess.section.Encrypt {
						err = os.Remove(lfilepath)
						if err != nil {
							log.Printf("clean error removing : %s, %s", lfilepath, err)
							c.bad = append(c.bad, FileError{path: path, err: err})
						}
						log.Printf("cleaned : %s", lfilepath)
					}
					err = os.Remove(lfilesrc)
					if err != nil {
						log.Printf("clean error removing : %s, %s", lfilesrc, err)
						c.bad = append(c.bad, FileError{path: path, err: err})
					}
					log.Printf("cleaned : %s", lfilesrc)

				}

				c.good = append(c.good, path)
			}

		}
	}

	// summarise results
	if len(c.good) > 0 {
		log.Printf("%d files successfully pushed\n", len(c.good))
		for i := range c.good {
			log.Printf("pushed: %s\n", c.good[i])
		}
	}
	if len(c.bad) > 0 {
		log.Printf("%d files had errors\n", len(c.bad))
		for i := range c.bad {
			log.Printf("not pushed: %s %s\n", c.bad[i].path, c.bad[i].err.Error())
		}
		return 1
	}

	return 0
}

func (c *PushCommand) Help() string {
	return "help: push files to a remote sftp server"
}

func (c *PushCommand) Synopsis() string {
	return "synopsis: push files to a remote sftp server"
}
