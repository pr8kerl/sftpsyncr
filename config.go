package main

type Config struct {
	Logfile  string
	LockDir  string
	Filemode uint32
	Debug    bool
	Profiles map[string]*Profile
}

type Profile struct {
	Server      string
	Username    string
	Password    string
	Key         string
	Port        uint32
	MatchRegExp string
	LocalDir    string
	RemoteDir   string
}
