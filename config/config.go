package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Port           int64  `mapstructure:"port" json:"port,omitempty"`
		Host           string `mapstructure:"host" json:"host,omitempty"`
		VaultsFilePath string `mapstructure:"vaults_file_path" json:"vaults_file_path,omitempty"`
	} `mapstructure:"server" json:"server"`

	Redis struct {
		Host     string `mapstructure:"host" json:"host,omitempty"`
		Port     string `mapstructure:"port" json:"port,omitempty"`
		User     string `mapstructure:"user" json:"user,omitempty"`
		Password string `mapstructure:"password" json:"password,omitempty"`
		DB       int    `mapstructure:"db" json:"db,omitempty"`
	} `mapstructure:"redis" json:"redis,omitempty"`

	Relay struct {
		Server string `mapstructure:"server" json:"server"`
	} `mapstructure:"relay" json:"relay,omitempty"`

	EmailServer struct {
		ApiKey string `mapstructure:"api_key" json:"api_key"`
	} `mapstructure:"email_server" json:"email_server"`

	BlockStorage struct {
		Host      string `mapstructure:"host" json:"host"`
		Region    string `mapstructure:"region" json:"region"`
		AccessKey string `mapstructure:"access_key" json:"access_key"`
		SecretKey string `mapstructure:"secret" json:"secret"`
		Bucket    string `mapstructure:"bucket" json:"bucket"`
	} `mapstructure:"block_storage" json:"block_storage"`

	VerificationServer struct {
		URL string `mapstructure:"url" json:"url"`
	} `mapstructure:"verification_server" json:"verification_server,omitempty"`
}

func GetConfigure() (*Config, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}
	
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("Server.Port", 8080)
	viper.SetDefault("Server.Host", "localhost")
	viper.SetDefault("Server.VaultsFilePath", "vaults")
	viper.SetDefault("Redis.Host", "localhost")
	viper.SetDefault("Redis.Port", "6379")
	viper.SetDefault("Redis.User", "")
	viper.SetDefault("Redis.Password", "")
	viper.SetDefault("Redis.DB", 0)
	viper.SetDefault("Relay.Server", "https://api.vultisig.com/router")
	viper.SetDefault("VerificationServer.URL", "")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg Config
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
