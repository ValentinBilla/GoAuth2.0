package utils

import (
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

var Config ConfigurationProperties

type ConfigurationProperties struct {
	OAuth struct {
		GrantCodeExpiration    time.Duration `yaml:"grant-code-expiration"`
		AccessTokenExpiration  time.Duration `yaml:"access-token-expiration"`
		RefreshTokenExpiration time.Duration `yaml:"refresh-token-expiration"`
		RefreshTokenLifetime   time.Duration `yaml:"refresh-token-lifetime"`
	} `yaml:"oauth"`

	JWT struct {
		SecretKey string `yaml:"secret-key"`
		Issuer    string `yaml:"issuer"`
	} `yaml:"jwt"`

	Redis struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Password string `yaml:"password"`
		Database int    `yaml:"database"`
	} `yaml:"redis"`
}

func LoadConfiguration() {
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(configFile, &Config)
	if err != nil {
		panic(err)
	}
}
