package main

import (
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"

	"github.com/vultisig/vultiserver/api"
	"github.com/vultisig/vultiserver/config"
	"github.com/vultisig/vultiserver/storage"
)

func main() {
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
