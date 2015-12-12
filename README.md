# sftpsyncr

An sftp cmd line client.
Allows syncing of entire directories to or from a remote sftp server.

Not yet complete.

Does push and pull.

## To do
* ~~http connect proxy support~~
* ~~set filemode or dirmode~~
* optional encrypt/decrypt of files
* remove files after transfer
* archive files after transfer
* run an optional custom script after each transfer
* run an optional custom script after complete transfer session

## Notes

### cbc support

Google group discussion [here](https://groups.google.com/forum/#!topic/Golang-nuts/J2XCsTsNQ9o)
Uncomment the cipher here:  https://github.com/golang/crypto/blob/master/ssh/cipher.go#L120

Using SciptRock/ssh and ScriptRock/sftp for now to support dodgy algos.
Neither sftp library appears to support compression atm.


