package infra

import (
	"GoAuth2.0/utils"
	"context"
	"github.com/redis/go-redis/v9"
)

type AuthorizationCodeCachedProperties struct {
	ClientId            string `json:"client_id"`
	RedirectUri         string `json:"redirect_uri"`
	Username            string `json:"username"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" required:"oneof=plain S256"`
}

func SaveAuthorizationCode(code string, properties AuthorizationCodeCachedProperties) error {
	key := "authorization-code:" + code

	ctx := context.Background()
	_, err := GetRedisClient().Pipelined(ctx, func(rdb redis.Pipeliner) error {
		rdb.HSet(ctx, key,
			"client_id", properties.ClientId,
			"redirect_uri", properties.RedirectUri,
			"username", properties.Username,
			"scope", properties.Scope,
			"code_challenge", properties.CodeChallenge,
			"code_challenge_method", properties.CodeChallengeMethod,
		)
		rdb.Expire(ctx, key, utils.Config.OAuth.GrantCodeExpiration)
		return nil
	})

	return err
}

func GetAuthorizationCode(code string) (AuthorizationCodeCachedProperties, error) {
	key := "authorization-code:" + code

	ctx := context.Background()
	properties, err := GetRedisClient().HGetAll(ctx, key).Result()
	if err != nil {
		return AuthorizationCodeCachedProperties{}, err
	}

	return AuthorizationCodeCachedProperties{
		ClientId:            properties["client_id"],
		RedirectUri:         properties["redirect_uri"],
		Username:            properties["username"],
		Scope:               properties["scope"],
		CodeChallenge:       properties["code_challenge"],
		CodeChallengeMethod: properties["code_challenge_method"],
	}, nil
}
