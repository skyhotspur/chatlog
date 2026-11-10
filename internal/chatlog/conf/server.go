package conf

import "strings"

const (
	// Loopback by default: the API serves decrypted chat history without
	// authentication unless http_token is set.
	DefalutHTTPAddr = "127.0.0.1:5030"
)

type ServerConfig struct {
	Type        string `mapstructure:"type"`
	Platform    string `mapstructure:"platform"`
	Version     int    `mapstructure:"version"`
	FullVersion string `mapstructure:"full_version"`
	DataDir     string `mapstructure:"data_dir"`
	DataKey     string `mapstructure:"data_key"`
	ImgKey      string `mapstructure:"img_key"`
	WorkDir     string `mapstructure:"work_dir"`
	HTTPAddr    string `mapstructure:"http_addr"`
	// HTTPToken, when set, is required on every request (Bearer header, ?token= or cookie).
	HTTPToken string `mapstructure:"http_token"`
	// HTTPAllowedHosts is a comma-separated list of extra Host names (besides IPs and localhost).
	HTTPAllowedHosts string   `mapstructure:"http_allowed_hosts"`
	AutoDecrypt      bool     `mapstructure:"auto_decrypt"`
	Webhook          *Webhook `mapstructure:"webhook"`
}

var ServerDefaults = map[string]any{}

func (c *ServerConfig) GetDataDir() string {
	return c.DataDir
}

func (c *ServerConfig) GetWorkDir() string {
	return c.WorkDir
}

func (c *ServerConfig) GetPlatform() string {
	return c.Platform
}

func (c *ServerConfig) GetVersion() int {
	return c.Version
}

func (c *ServerConfig) GetDataKey() string {
	return c.DataKey
}

func (c *ServerConfig) GetImgKey() string {
	return c.ImgKey
}

func (c *ServerConfig) GetAutoDecrypt() bool {
	return c.AutoDecrypt
}

func (c *ServerConfig) GetHTTPAddr() string {
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefalutHTTPAddr
	}
	return c.HTTPAddr
}

func (c *ServerConfig) GetHTTPToken() string {
	return c.HTTPToken
}

func (c *ServerConfig) GetHTTPAllowedHosts() []string {
	if c.HTTPAllowedHosts == "" {
		return nil
	}
	return strings.Split(c.HTTPAllowedHosts, ",")
}

// Redacted returns a copy that is safe to log.
func (c ServerConfig) Redacted() ServerConfig {
	c.DataKey = redact(c.DataKey)
	c.ImgKey = redact(c.ImgKey)
	c.HTTPToken = redact(c.HTTPToken)
	return c
}

func redact(secret string) string {
	if secret == "" {
		return ""
	}
	return "***"
}

func (c *ServerConfig) GetWebhook() *Webhook {
	return c.Webhook
}
