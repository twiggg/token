package token

import (
	"fmt"
	"testing"
)

var keypicker KeySlice = []string{"1K9l8985", "1a9s8n8", "1a2b3c4d"}

func TestVerify(t *testing.T) {
	token1, _ := New(keypicker, "bcrypt", "issuer", "laahs", "admin", "private", "twiggg,pticreu", "", 24*12)
	head, claims, signature, err := Parse(token)

	tests := []struct {
		token string
		want  bool
	}{
		{token1, true},
	}

	for _, v := range tests {
		Parse(v)
	}
}
