package oauth

import "testing"

func Test_verifyCodeChallenge(t *testing.T) {
	type args struct {
		challenge string
		method    string
		verifier  string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Test S256 code challenge",
			args: args{
				challenge: "PDx_W-BAoMrTES0ctlHBdgCK6oD8-cLVL7kGFrx-h0U",
				method:    "S256",
				verifier:  "HzX652XK7nUPMVW3Sun_MYe0sWepUO6r4KKeApjg0H_EPtl4",
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyCodeChallenge(tt.args.challenge, tt.args.method, tt.args.verifier)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyCodeChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("verifyCodeChallenge() got = %v, want %v", got, tt.want)
			}
		})
	}
}
