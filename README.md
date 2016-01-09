# sftpsyncr

An sftp cmd line client.
Allows syncing of entire directories to or from a remote sftp server.

### Features

* optionally remove files on remote side after transfer
* optionally archive/copy transferred files to a local archive directory
* openpgp encryption and decryption of files
* http connect proxy support (no auth)
* optional alert email on failure or success 
* optionally check file size after a period to ensure size is stable before transfer

Usable.

# Setup

* clone the repo

* pull in golang dependencies

```
make deps
```

* build the binary

```
make
```

* create the config file

```
cp config.example config.ini
```

* edit the config to suit your needs

# configuration

Take a look in **config.example** for what configuration is available.

In the config file, you can define multiple "profiles". A single invocation of the sftpsyncr command must specify a single profile to use. A profile defines the connection sftp settings such as remote host, remote port, username etc.
The defaults section is where you can define configurables that will apply to all profiles, if said configurable is not defined within the specific profile.

Password or ssh public key authentication can be used. ssh-agent can also be used by setting the environment **SSH_AUTH_SOCK** appropriately and disabling the **password** and **key** configurables.

Files can be encrypted prior to transfer, and decrypted after transfer. Use the public key ID only to identify the key to use. 

An HTTP connect proxy can also be used (such as squid or apache). No proxy authentication methods are supported. 

A single encryption key can be defined to encrypt ALL files to be transferred.
Multiple decryption keys keys can be used to decrypt files with a specific suffix.

## Decryption

You can specify multiple decryption keys and passphrases within a profile. But they MUST be specified in their correct matching order.
The reason is that the configuration package reads multiple values in to an array. So the passphrase for a key must have the same array index.
It's easier for me this way - I am lazy. But it works fine if your config is correct.

Example config for multiple decryption keys:

```
decrypt = true
decryptsuffix = ".gpg"
decryptkeyid = 641E9413
decryptpassphrase = passphrase_for_key_641E9413
decryptkeyid = 3D0A8209
decryptpassphrase = passphrase_for_key_3D0A8209
```

In the above, only files with suffix of .gpg will be decrypted (or attempted to be decrypted).
The order of key id's and passphrases is critical.

The following config will fail to decrypt files as the passphrases will be set to the wrong key.
```
decrypt = true
decryptsuffix = ".gpg"
decryptkeyid = 641E9413
decryptpassphrase = passphrase_for_key_3D0A8209
decryptkeyid = 3D0A8209
decryptpassphrase = passphrase_for_key_641E9413
```

## Encryption

Only a single encryption key (recipient) is supported. You can also specify the suffix for the resulting encrypted file using the *encryptsuffix* configurable. The default encryption suffix is *.pgp*.

# examples

## command help

### subcommands

```
ians@module:~/work/sftpsyncr$ ./sftpsyncr --help
usage: sftpsyncr [--version] [--help] <command> [<args>]

Available commands are:
    pull    synopsis: pull files from a remote sftp server
    push    synopsis: push files to a remote sftp server

ians@module:~/work/sftpsyncr$
```

### options to subcommands
```
ians@module:~/work/sftpsyncr$ ./sftpsyncr pull --help
Usage of pull:
  -config string
    	config file in git config ini format (default "config.ini")
  -profile string
    	sftp session profile to use (default "default")
ians@module:~/work/sftpsyncr$ 
```

## run an sftp transfer

```
ians@module:~/work/sftpsyncr$ ./sftpsyncr pull --config config.ini --profile tester
2016/01/05 21:36:13 start tester
2016/01/05 21:36:13 connect to localhost:22
2016/01/05 21:36:13 pull file remote/wunderbike.png, 231903 bytes in 15.939313ms
2016/01/05 21:36:13 pull file remote/hosts.gpg, 1524 bytes in 820.43µs
2016/01/05 21:36:13 pull decrypted file /tmp/local/hosts.gpg to /tmp/local/hosts
2016/01/05 21:36:13 pull directory remote/subdir
2016/01/05 21:36:13 pull file remote/subdir/wordpress-logo-notext-rgb.png, 18399 bytes in 1.259507ms
2016/01/05 21:36:13 3 files successfully pulled
2016/01/05 21:36:13 pulled: wunderbike.png
2016/01/05 21:36:13 pulled: hosts.gpg
2016/01/05 21:36:13 pulled: subdir/wordpress-logo-notext-rgb.png
2016/01/05 21:36:13 end tester
ians@module:~/work/sftpsyncr$
```

## To do
* ~~http connect proxy support~~
* ~~set filemode same as source file~~
* ~~optional encrypt/decrypt of files~~
* ~~remove files after transfer~~
* ~~archive files after transfer~~
* ~~email logfile after success and/or failure~~
* run an optional custom script after transfer session

## Notes

### cbc support

Google group discussion [here](https://groups.google.com/forum/#!topic/Golang-nuts/J2XCsTsNQ9o)
Uncomment the cipher here:  https://github.com/golang/crypto/blob/master/ssh/cipher.go#L120

Using SciptRock/ssh and ScriptRock/sftp for now to support dodgy algos.

Neither sftp library appears to support compression atm.

### GPG

Golang GPG examples (here)[http://julianyap.com/2014/07/04/gnu-privacy-guard-gpg-examples-using-golang.html]. Thanks Julian!

