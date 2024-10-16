package utils

import (
	"encoding/base64"
	"math/rand"
	"strings"
)

func GenerateRandomCode() string {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)

	code := base64.URLEncoding.EncodeToString(randomBytes)
	return strings.TrimRight(code, "=")
}
