package infra

import (
	"GoAuth2.0/utils"
	"context"
	"github.com/redis/go-redis/v9"
)

type RefreshTokenCachedProperties struct {
	ClientId  string `json:"client_id"`
	Username  string `json:"username"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"expires_at"`
	IsValid   bool   `json:"is_valid"`

	// RotatedToken is the newly created token that was created using this one
	RotatedToken string `json:"rotated_token"`
}

func SaveRefreshToken(code string, properties RefreshTokenCachedProperties) error {
	key := "refresh-token:" + code

	ctx := context.Background()
	_, err := GetRedisClient().Pipelined(ctx, func(rdb redis.Pipeliner) error {
		rdb.HSet(ctx, key,
			"client_id", properties.ClientId,
			"username", properties.Username,
			"scope", properties.Scope,
			"expires_at", properties.ExpiresAt,
			"is_valid", properties.IsValid,
			"rotated_token", properties.RotatedToken,
		)
		rdb.Expire(ctx, key, utils.Config.OAuth.RefreshTokenLifetime)
		return nil
	})

	return err
}

func InvalidateRefreshToken(token string) error {
	key := "refresh-token:" + token

	ctx := context.Background()
	_, err := GetRedisClient().HSet(ctx, key, "is_valid", false).Result()
	return err
}

func SetRotatedToken(oldToken string, newToken string) error {
	key := "refresh-token:" + oldToken

	ctx := context.Background()
	_, err := GetRedisClient().Pipelined(ctx, func(rdb redis.Pipeliner) error {
		rdb.HSet(ctx, key, "is_valid", false)
		rdb.HSet(ctx, key, "rotated_token", newToken)
		return nil
	})
	return err
}

// CompromiseRefreshToken invalidates a refresh token and its rotated tokens in Redis to prevent unauthorized use.
func CompromiseRefreshToken(token string) error {
	ctx := context.Background()
	redisClient := GetRedisClient()

	for {
		key := "refresh-token:" + token
		err := redisClient.HSet(ctx, key, "is_valid", false).Err()
		if err != nil {
			return err
		}

		token, err := redisClient.HGet(ctx, key, "rotated_token").Result()
		if err != nil {
			return err
		}

		if token == "" {
			break
		}
	}

	return nil
}

func GetRefreshToken(token string) (RefreshTokenCachedProperties, error) {
	key := "refresh-token:" + token
	var properties RefreshTokenCachedProperties

	ctx := context.Background()
	err := GetRedisClient().HGetAll(ctx, key).Scan(&properties)
	if err != nil {
		return RefreshTokenCachedProperties{}, err
	}

	return properties, nil
}
