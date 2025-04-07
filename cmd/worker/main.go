package main

import (
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/vultisigner/config"
	"github.com/vultisig/vultisigner/internal/tasks"
	"github.com/vultisig/vultisigner/service"
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
	blockStorage, err := storage.NewBlockStorage(*cfg)
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
	workerServce, err := service.NewWorker(*cfg, client, sdClient, blockStorage)
	if err != nil {
		panic(err)
	}

	srv := asynq.NewServer(
		redisOptions,
		asynq.Config{
			Logger:      logrus.StandardLogger(),
			Concurrency: 10,
			Queues: map[string]int{
				tasks.QUEUE_NAME:       10,
				tasks.EMAIL_QUEUE_NAME: 100,
			},
		},
	)

	// mux maps a type to a handler
	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeKeyGeneration, workerServce.HandleKeyGeneration)
	mux.HandleFunc(tasks.TypeKeySign, workerServce.HandleKeySign)
	mux.HandleFunc(tasks.TypeEmailVaultBackup, workerServce.HandleEmailVaultBackup)
	mux.HandleFunc(tasks.TypeReshare, workerServce.HandleReshare)
	mux.HandleFunc(tasks.TypeKeyGenerationDKLS, workerServce.HandleKeyGenerationDKLS)
	mux.HandleFunc(tasks.TypeKeySignDKLS, workerServce.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, workerServce.HandleReshareDKLS)
	mux.HandleFunc(tasks.TypeMigrate, workerServce.HandleMigrateDKLS)
	if err := srv.Run(mux); err != nil {
		panic(fmt.Errorf("could not run server: %w", err))
	}
}
