package hmac

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/kalrashubham49/fosite"
	signingutils "github.com/kalrashubham49/fosite/signing_utils"
)

// HMACStrategy is responsible for generating and validating challenges.
type HMACStrategy struct {
	TokenEntropy         int
	GlobalSecret         []byte
	RotatedGlobalSecrets [][]byte
	PrivateKey           *rsa.PrivateKey
	sync.Mutex
}

// Generate generates a token and a matching signature or returns an error.
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets.
func (c *HMACStrategy) Generate() (string, string, error) {
	c.Lock()
	defer c.Unlock()

	if c.PrivateKey == nil {
		return "", "", errors.Errorf("No Private Key Found")
	}

	if len(c.GlobalSecret) < minimumSecretLength {
		return "", "", errors.Errorf("secret for signing HMAC-SHA256 is expected to be 32 byte long, got %d byte", len(c.GlobalSecret))
	}

	var signingKey [32]byte
	copy(signingKey[:], c.GlobalSecret)

	if c.TokenEntropy < minimumEntropy {
		c.TokenEntropy = minimumEntropy
	}

	// When creating secrets not intended for usage by human users (e.g.,
	// client secrets or token handles), the authorization server should
	// include a reasonable level of entropy in order to mitigate the risk
	// of guessing attacks.  The token value should be >=128 bits long and
	// constructed from a cryptographically strong random or pseudo-random
	// number sequence (see [RFC4086] for best current practice) generated
	// by the authorization server.
	tokenKey, err := RandomBytes(c.TokenEntropy)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	signature := generateHMAC(tokenKey, &signingKey)
	expiryTime := time.Now().Add(3600).UTC().Unix()
	expiryTimeString := fmt.Sprintf("%v", expiryTime)
	token := fmt.Sprintf("%s.%s.%s", string(tokenKey), expiryTimeString, string(signature))
	encodedToken := b64.EncodeToString([]byte(token))

	// Sign The Encoded token and Generate signature

	signedSignature, err := signingutils.SignToken(encodedToken, c.PrivateKey)

	if err != nil {
		return "", "", errors.WithStack(err)
	}
	// Use Signing Utils to Sign the Encoded Token

	encodedSignatureString := b64.EncodeToString(signedSignature)
	signedToken := fmt.Sprintf("%s.%s", encodedToken, encodedSignatureString)
	return signedToken, encodedSignatureString, nil

}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (c *HMACStrategy) Validate(token string) (err error) {
	var keys [][]byte

	if len(c.GlobalSecret) > 0 {
		keys = append(keys, c.GlobalSecret)
	}

	if len(c.RotatedGlobalSecrets) > 0 {
		keys = append(keys, c.RotatedGlobalSecrets...)
	}

	for _, key := range keys {
		if err = c.validate(key, token); err == nil {
			return nil
		} else if errors.Cause(err) == fosite.ErrTokenSignatureMismatch {
		} else {
			return err
		}
	}

	if err == nil {
		return errors.New("a secret for signing HMAC-SHA256 is expected to be defined, but none were")
	}

	return err
}

func (c *HMACStrategy) validate(secret []byte, token string) error {

	if len(secret) < minimumSecretLength {
		return errors.Errorf("secret for signing HMAC-SHA256 is expected to be 32 byte long, got %d byte", len(secret))
	}

	var signingKey [32]byte
	copy(signingKey[:], secret)

	split := strings.Split(token, ".")
	if len(split) != 2 {
		return errors.WithStack(fosite.ErrInvalidTokenFormat)
	}

	tokenKey := split[0]
	tokenSignature := split[1]

	if tokenKey == "" || tokenSignature == "" {
		return errors.WithStack(fosite.ErrInvalidTokenFormat)
	}

	decodedTokenSignature, err := b64.DecodeString(tokenSignature)
	if err != nil {
		return errors.WithStack(err)
	}

	return signingutils.VerifySigning(&c.PrivateKey.PublicKey, token, decodedTokenSignature)

	// decodedTokenKey, err := b64.DecodeString(tokenKey)
	// if err != nil {
	// 	return errors.WithStack(err)
	// }

	// // CHECK WITH LOKESH SIR======================
	// // TODO: If verifier successfuly , do we still need to generate HMAC anc Check
	// expectedMAC := generateHMAC(decodedTokenKey, &signingKey)
	// if !hmac.Equal(expectedMAC, decodedTokenSignature) {
	// 	// Hash is invalid
	// 	return errors.WithStack(fosite.ErrTokenSignatureMismatch)
	// }

	// return nil
}

//Signature - Return Signature Out of HmacToken
func (c *HMACStrategy) Signature(token string) string {
	split := strings.Split(token, ".")
	// Changed Characters Limit to 3 , As we have added Expiry Time to Encoded Key
	if len(split) != 2 {
		return ""
	}
	return split[1]
}

//Valid - Check for Expiry of HMAC Token
func (c *HMACStrategy) Valid(token string) bool {
	expiry, err := c.GetExpirationTime(token)
	if err != nil {
		return false
	}
	isExpired := time.Now().UTC().After(expiry)

	// Returning Expiry Status of Token
	return !isExpired

}

//GetExpirationTime -  Get Expiration Time from Token in UTC
func (c *HMACStrategy) GetExpirationTime(token string) (time.Time, error) {

	components := strings.Split(token, ".")
	if len(components) != 2 {
		return time.Now(), errors.New("Invalid Token")
	}
	encodedToken := components[0]
	tokenData, err := b64.DecodeString(encodedToken)

	if err != nil {
		return time.Now(), errors.New("Invalid Token")
	}

	tokenString := string(tokenData)

	tokenComponents := strings.Split(tokenString, ".")

	expiry, err := time.Parse(time.Stamp, tokenComponents[1])

	if err != nil {
		return time.Now(), errors.New("Invalid Token")
	}
	return expiry, nil
}

func GenerateSignedHMAC(data []byte, key *[32]byte) []byte {
	h := hmac.New(sha512.New512_256, key[:])
	h.Write(data)
	return h.Sum(nil)
}
