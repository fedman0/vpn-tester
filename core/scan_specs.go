package main

type sshSpec struct {
	Name       string
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey []byte
	Mode       string
	SNI        string
	ProxyHost  string
	ProxyPort  int
	Payload    string
	WSPath     string
	WSHost     string
	UserAgent  string
	DNSTT      *dnsttSpec
}

type dnsttSpec struct {
	Name       string
	Domain     string
	PublicKey  string
	Resolvers  []string
	Transport  string
	RecordType string
	Variant    string
	Upstream   string
	SocksUser  string
	SocksPass  string
	SSH        *sshSpec
}

var (
	buildSSHConfig   func(f *vfile, fs *vfs, s *sshSpec) *Config
	buildDNSTTConfig func(f *vfile, fs *vfs, s *dnsttSpec) *Config
)

func sshConfig(f *vfile, fs *vfs, s *sshSpec) *Config {
	if buildSSHConfig == nil {
		c := unsupportedConfig(f, "SSH", "SSH", "SSH tunnel support is not available")
		c.Name, c.Host, c.Port = s.Name, s.Host, s.Port
		return c
	}
	return buildSSHConfig(f, fs, s)
}

func dnsttConfig(f *vfile, fs *vfs, s *dnsttSpec) *Config {
	if buildDNSTTConfig == nil {
		c := unsupportedConfig(f, "SlowDNS", "DNSTT", "DNS tunnel support is not available")
		c.Name, c.Host = s.Name, s.Domain
		return c
	}
	return buildDNSTTConfig(f, fs, s)
}
