package signingutils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/kalrashubham49/fosite/authentication"
)

func ConvertStringToPrivateKey(key string) (*rsa.PrivateKey, error) {

	secret, err := authentication.DecodePemToPrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func ConvertPrivateKeyToString(privateKey *rsa.PrivateKey) string {

	privateKeyData := authentication.EncodePrivateKeyToPEM(privateKey)
	return string(privateKeyData)
}

func SignToken(token string, privateKey *rsa.PrivateKey) ([]byte, error) {

	hashedMessage := sha256.Sum256([]byte(token))
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedMessage[:])
}

func VerifySigning(publicKey *rsa.PublicKey, token string, signature []byte) error {
	// VERIFY USING PUBLIC KEY
	hashedTokenKey := sha256.Sum256([]byte(token))
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedTokenKey[:], signature)
}
