package main

import (
	"flag"
	"github.com/mitchellh/cli"
	"log"
	"os"
	"path/filepath"
	"time"
)

type PullCommand struct {
	Ui cli.Ui
}

func pullCmdFactory() (cli.Command, error) {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	return &PullCommand{
		Ui: &cli.ColoredUi{
			Ui:          ui,
			OutputColor: cli.UiColorBlue,
		},
	}, nil
}

func (c *PullCommand) Run(args []string) int {

	// flags
	var cfgfile string
	var err error
	xferverb = "received"
	cmdFlags := flag.NewFlagSet("pull", flag.ContinueOnError)
	cmdFlags.StringVar(&profile, "profile", "default", "sftp session profile to use")
	cmdFlags.StringVar(&cfgfile, "config", "config.ini", "config file in git config ini format")
	if err = cmdFlags.Parse(args); err != nil {
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

	// build remote file list
	err = sess.WalkRemote()
	if err != nil {
		log.Printf("unable to walk remote server: %v\n", err)
		return 95
	}

	// if file list connect
	if len(sess.RemoteFiles) > 0 {

		var archivepath string

		// build local file list
		filepath.Walk(sess.section.LocalDir, sess.WalkLocal)

		// for each remote file, do a pre-check, create directory structure
		// save files not local to GetFiles map
		for path := range sess.RemoteFiles {

			var lsize, rsize int64 = 0, 0
			lfinfo, lexists := sess.LocalFiles[path]

			rfinfo := sess.RemoteFiles[path]
			rsize = rfinfo.Size()

			rmode := rfinfo.Mode()
			if rfinfo.IsDir() {

				if debug {
					log.Printf("DEBUG processing remote directory : %s, %d\n", path, rsize)
				}

				// prepend the remote dir to the remote file path
				//rfilepath := filepath.Join(sess.section.RemoteDir, path)
				// prepend the local dir to the local file path
				lfilepath := filepath.Join(sess.section.LocalDir, path)

				// test for local directory
				if _, err := os.Stat(lfilepath); err != nil {
					if os.IsNotExist(err) {
						// dir does not exist
						// kludge - ensure perms has 0700 as a minimum. Some sftp servers don't show executable bit on dirs.
						rmode |= 0700
						err = os.MkdirAll(lfilepath, rmode)
						if err != nil {
							log.Printf("error creating local directory path : %s, %s\n", lfilepath, err)
						}
						if debug {
							log.Printf("directory perm before : %s, %s\n", lfilepath, rmode.String())
							log.Printf("DEBUG created local dir %s\n", lfilepath)
						}
					}
				}

				if archive {

					archivepath = filepath.Join(sess.section.ArchiveDir, path)
					if _, err := os.Stat(archivepath); err != nil {
						if os.IsNotExist(err) {
							// dir does not exist
							err = os.MkdirAll(archivepath, rmode)
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

			if debug {
				log.Printf("DEBUG processing remote file : %s, %d\n", path, rsize)
			}

			if lexists {
				lsize = lfinfo.Size()
			}

			// ignore if it is on local
			if lexists && lsize == rsize {

				if debug {
					log.Printf("DEBUG path %s already exists on local with size %d bytes\n", path, lsize)
				}

				continue

			} else {

				sess.GetFiles[path] = rfinfo
			}

		}

		pcount := len(sess.GetFiles)
		if pcount > 0 {
			log.Printf("found %d remote files eligible for download\n", pcount)
		} else {
			log.Printf("no remote files eligible for download.\n")
			return 0
		}

		// if stable check enabled, wait StableDuration seconds
		if stable {
			log.Printf("stable check enabled - pausing for %d to confirm remote file size stability\n", stableblock)
			time.Sleep(time.Duration(stableblock) * time.Second)
			log.Printf("stable check pause complete.\n")
		}

		for path := range sess.GetFiles {

			rfinfo := sess.GetFiles[path]
			rsize := rfinfo.Size()
			rmode := rfinfo.Mode()

			// prepend the remote dir to the remote file path
			rfilepath := filepath.Join(sess.section.RemoteDir, path)
			// prepend the local dir to the local file path
			lfilepath := filepath.Join(sess.section.LocalDir, path)

			if stable {
				csize, err := sess.GetRemoteSize(rfilepath)
				if err != nil {
					log.Printf("error checking remote file size, skipping : %s\n", err)
				}
				if csize != rsize {
					log.Printf("file %s size is not stable, skipping. current size: %d bytes, initial size: %d\n", path, csize, rsize)
					continue
				}
			}

			err = sess.Pull(rfilepath, lfilepath, rsize, rmode)
			if err != nil {
				log.Printf("error pulling file : %s %s\n", path, err)
				sess.Bad = append(sess.Bad, FileError{path: path, err: err})
				// bail??
				continue
			}

			if archive {
				archivepath = filepath.Join(sess.section.ArchiveDir, path)
				// copy lfilepath to archivepath
				err = sess.CopyFile(lfilepath, archivepath)
				if err != nil {
					log.Printf("error archiving file : %s %s\n", path, err)
					sess.Bad = append(sess.Bad, FileError{path: path, err: err})
					continue
				}
				if debug {
					log.Printf("DEBUG archive file %s\n", archivepath)
				}
			}
			var dcrypted string
			if sess.section.Decrypt {

				if matched := sess.Dcryptregexp.MatchString(path); matched {
					dcrypted, err = sess.DecryptFile(lfilepath)
					if err != nil {
						log.Printf("error decrypting file : %s %s\n", lfilepath, err)
						sess.Bad = append(sess.Bad, FileError{path: path, err: err})
						continue
					}
					log.Printf("decrypted file %s to %s\n", lfilepath, dcrypted)

					if sess.section.CleanDecrypted {
						// clean up the original encrypted file
						err = os.Remove(lfilepath)
						if err != nil {
							log.Printf("clean error removing : %s, %s", lfilepath, err)
							sess.Bad = append(sess.Bad, FileError{path: path, err: err})
						}
						if debug {
							log.Printf("cleaned encrypted file: %s", lfilepath)
						}
					}
				}

			}

			if sess.section.Reencrypt {
				var file string
				if sess.section.Decrypt {
					file = dcrypted
				} else {
					file = lfilepath
				}

				efile, _, err := sess.EncryptFile(file)
				if err != nil {
					log.Printf("error re-encrypting file : %s, %s\n", file, err)
					sess.Bad = append(sess.Bad, FileError{path: path, err: err})
					continue
				}
				log.Printf("re-encrypted file: %s\n", efile)

			}
			if clean {
				err = sess.RemoveRemote(rfilepath)
				if err != nil {
					log.Printf("error removing remote file : %s %s\n", path, err)
					sess.Bad = append(sess.Bad, FileError{path: path, err: err})
					continue
				}
			}
			sess.Good = append(sess.Good, path)
		}
	}

	// summarise results
	if len(sess.Good) > 0 {
		log.Printf("%d files successfully pulled\n", len(sess.Good))
		for i := range sess.Good {
			log.Printf("pulled: %s\n", sess.Good[i])
		}
	}
	if len(sess.Bad) > 0 {
		log.Printf("%d files had errors\n", len(sess.Bad))
		for i := range sess.Bad {
			log.Printf("not pulled: %s %s\n", sess.Bad[i].path, sess.Bad[i].err.Error())
		}
		return 1
	}

	return 0

}

func (c *PullCommand) Help() string {
	return "help: pull files from a remote sftp server"
}

func (c *PullCommand) Synopsis() string {
	return "synopsis: pull files from a remote sftp server"
}
