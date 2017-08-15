package auth

import (
	"testing"
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/stretchr/testify/assert"
	"fmt"
	"encoding/base64"
)

func TestEcdsaSignAndVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	assert.Nil(t, err)
	digest := []byte("hello")
	sig, err := EcdsaSign(digest, priv)
	if err != nil {
		fmt.Println(err)
	}
	assert.Nil(t, err)
	err = EcdsaVerify(digest, sig, &(priv.PublicKey))
	if err != nil {
		fmt.Println(err)
	}
	assert.Nil(t, err)
}

func TestBase64Encoding(t *testing.T) {
	fmt.Println(base64.StdEncoding.EncodeToString([]byte("abc")))
	fmt.Println(base64.URLEncoding.EncodeToString([]byte("abc")))
}