package customopenid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/kalrashubham49/fosite"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	GenerateNewIDToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
}

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
	Storage         OpenIDConnectRequestStorage
	IDTokenLifeSpan time.Duration
}

func (i *IDTokenHandleHelper) GetAccessTokenHash(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) string {
	token := responder.GetAccessToken()

	buffer := bytes.NewBufferString(token)
	hash := sha256.New()
	hash.Write(buffer.Bytes())
	hashBuf := bytes.NewBuffer(hash.Sum([]byte{}))
	len := hashBuf.Len()

	return base64.RawURLEncoding.EncodeToString(hashBuf.Bytes()[:len/2])
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, fosr fosite.Requester) (token string, signauture string, err error) {
	token, signature, err := i.IDTokenStrategy.GenerateIDToken(ctx, fosr)
	if err != nil {
		return "", "", err
	}

	return token, signature, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, ar fosite.Requester, resp fosite.AuthorizeResponder) error {
	token, signature, err := i.generateIDToken(ctx, ar)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	} else if err = i.Storage.CreateOpenIDConnectSession(ctx, signature, ar); err != nil {
		return err
	}

	resp.AddFragment("id_token", token)
	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, ar fosite.Requester, resp fosite.AccessResponder) error {
	token, signature, err := i.generateIDToken(ctx, ar)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	} else if err = i.Storage.CreateOpenIDConnectSession(ctx, signature, ar); err != nil {
		return err
	}

	resp.SetExtra("id_token", token)
	return nil
}

func (i *IDTokenHandleHelper) IssueIDToken(ctx context.Context, fosr fosite.Requester, resp fosite.AccessResponder) (err error) {

	token, signature, err := i.IDTokenStrategy.GenerateNewIDToken(ctx, fosr)
	if err != nil {
		return err
	} else if err = i.Storage.CreateOpenIDConnectSession(ctx, signature, fosr); err != nil {
		return err
	}
	resp.SetExtra("id_token", token)
	return nil
}
