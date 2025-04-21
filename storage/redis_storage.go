package storage

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vultisig/vultiserver/config"
	"github.com/vultisig/vultiserver/contexthelper"
)

type RedisStorage struct {
	cfg    config.Config
	client *redis.Client
}

func NewRedisStorage(cfg config.Config) (*RedisStorage, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	status := client.Ping(context.Background())
	if status.Err() != nil {
		return nil, status.Err()
	}
	return &RedisStorage{
		cfg:    cfg,
		client: client,
	}, nil
}

func (r *RedisStorage) Get(ctx context.Context, key string) (string, error) {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return "", err
	}
	return r.client.Get(ctx, key).Result()
}
func (r *RedisStorage) Set(ctx context.Context, key string, value string, expiry time.Duration) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Set(ctx, key, value, expiry).Err()
}
func (r *RedisStorage) Expire(ctx context.Context, key string, expiry time.Duration) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Expire(ctx, key, expiry).Err()
}
func (r *RedisStorage) Delete(ctx context.Context, key string) error {
	if err := contexthelper.CheckCancellation(ctx); err != nil {
		return err
	}
	return r.client.Del(ctx, key).Err()
}
func (r *RedisStorage) Close() error {
	return r.client.Close()
}
