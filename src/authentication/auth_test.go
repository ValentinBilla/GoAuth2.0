package authentication

import (
	"testing"
)

func TestVerifyScope(t *testing.T) {
	tests := []struct {
		name          string
		requiredScope string
		userScope     string
		want          bool
	}{
		{
			name:          "scopes are equal",
			requiredScope: "scope1 scope2",
			userScope:     "scope1 scope2",
			want:          true,
		},
		{
			name:          "required scope is a part of user scope",
			requiredScope: "scope1",
			userScope:     "scope1 scope2",
			want:          true,
		},
		{
			name:          "user scope is absent",
			requiredScope: "scope1 scope2",
			userScope:     "",
			want:          false,
		},
		{
			name:          "user scope does not contain required scope",
			requiredScope: "scope1",
			userScope:     "scope2 scope3",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyScope(tt.requiredScope, tt.userScope); got != tt.want {
				t.Errorf("verifyScope() = %v, want %v", got, tt.want)
			}
		})
	}
}
