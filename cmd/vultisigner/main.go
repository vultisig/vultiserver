package main

import (
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"

	"github.com/vultisig/vultisigner/api"
	"github.com/vultisig/vultisigner/config"
	"github.com/vultisig/vultisigner/storage"
)

func main() {
	// Load all configuration at startup.
	// The VS_CONFIG_NAME environment variable controls which config file is loaded.
	// This config is used throughout the application and should not be reloaded at runtime.
	cfg, err := config.GetConfigure()
	if err != nil {
		panic(err)
	}

	sdClient, err := statsd.New("127.0.0.1:8125")
	if err != nil {
		panic(err)
	}
	port := cfg.Server.Port

	redisStorage, err := storage.NewRedisStorage(*cfg)
	if err != nil {
		panic(err)
	}
	redisOptions := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	client := asynq.NewClient(redisOptions)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Println("fail to close asynq client,", err)
		}
	}()
	inspector := asynq.NewInspector(redisOptions)
	if cfg.Server.VaultsFilePath == "" {
		panic("vaults file path is empty")

	}
	blockStorage, err := storage.NewBlockStorage(*cfg)
	if err != nil {
		panic(err)
	}
	server := api.NewServer(port,
		redisStorage,
		client,
		inspector,
		cfg.Server.VaultsFilePath, sdClient, blockStorage)
	if err := server.StartServer(); err != nil {
		panic(err)
	}
}
