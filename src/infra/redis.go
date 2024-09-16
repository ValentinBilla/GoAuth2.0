package infra

import (
	"GoAuth2.0/utils"
	"fmt"
	"github.com/redis/go-redis/v9"
)

var redisClient *redis.Client

func GetRedisClient() *redis.Client {
	if redisClient != nil {
		return redisClient
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", utils.Config.Redis.Host, utils.Config.Redis.Port),
		Password: utils.Config.Redis.Password,
		DB:       utils.Config.Redis.Database,
	})
	return redisClient
}

func CloseRedisClient() {
	if redisClient != nil {
		_ = redisClient.Close()
	}
}
