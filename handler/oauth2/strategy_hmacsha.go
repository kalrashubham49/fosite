/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/kalrashubham49/fosite"
	enigma "github.com/kalrashubham49/fosite/token/hmac"
)

type HMACSHAStrategy struct {
	Enigma                *enigma.HMACStrategy
	AccessTokenLifespan   time.Duration
	RefreshTokenLifespan  time.Duration
	AuthorizeCodeLifespan time.Duration
}

func (h HMACSHAStrategy) AccessTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) RefreshTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) AuthorizeCodeSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategy) GenerateAccessToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAccessToken(_ context.Context, r fosite.Requester, token string) (err error) {

	err = h.Enigma.Validate(token)
	if err != nil { // Validation Error
		return err
	}

	// Check for Expiry
	isExpired := h.Enigma.Valid(token)
	if isExpired == true {
		return errors.New("Token Expired")
	}

	var exp = r.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AccessTokenLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at \"%s\".", r.GetRequestedAt().Add(h.AccessTokenLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at \"%s\".", exp))
	}

	return nil
}

func (h HMACSHAStrategy) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateRefreshToken(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(token)
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Refresh token expired at \"%s\".", exp))
	}
	return h.Enigma.Validate(token)

}

func (h HMACSHAStrategy) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAuthorizeCode(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AuthorizeCodeLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", r.GetRequestedAt().Add(h.AuthorizeCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", exp))
	}
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) AuthorizeHmacSignatute(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) GenerateAuthorizeHmacCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}
func (h HMACSHAStrategy) ValidateAuthorizeHmacCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	var exp = requester.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && requester.GetRequestedAt().Add(h.AuthorizeCodeLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", requester.GetRequestedAt().Add(h.AuthorizeCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", exp))
	}
	return h.Enigma.Validate(token)
}

type HMACSHAStrategyWithoutSigning struct {
	Enigma                *enigma.OldHMACStrategy
	AccessTokenLifespan   time.Duration
	RefreshTokenLifespan  time.Duration
	AuthorizeCodeLifespan time.Duration
}

func (h HMACSHAStrategyWithoutSigning) AccessTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategyWithoutSigning) RefreshTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategyWithoutSigning) AuthorizeCodeSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategyWithoutSigning) GenerateAccessToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategyWithoutSigning) ValidateAccessToken(_ context.Context, r fosite.Requester, token string) (err error) {

	err = h.Enigma.Validate(token)
	if err != nil { // Validation Error
		return err
	}

	// Check for Expiry
	var exp = r.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AccessTokenLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at \"%s\".", r.GetRequestedAt().Add(h.AccessTokenLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at \"%s\".", exp))
	}

	return nil
}

func (h HMACSHAStrategyWithoutSigning) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategyWithoutSigning) ValidateRefreshToken(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(token)
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Refresh token expired at \"%s\".", exp))
	}
	return h.Enigma.Validate(token)

}

func (h HMACSHAStrategyWithoutSigning) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategyWithoutSigning) ValidateAuthorizeCode(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AuthorizeCodeLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", r.GetRequestedAt().Add(h.AuthorizeCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", exp))
	}

	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategyWithoutSigning) AuthorizeHmacSignatute(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategyWithoutSigning) GenerateAuthorizeHmacCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}
func (h HMACSHAStrategyWithoutSigning) ValidateAuthorizeHmacCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	var exp = requester.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && requester.GetRequestedAt().Add(h.AuthorizeCodeLifespan).Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", requester.GetRequestedAt().Add(h.AuthorizeCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errors.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at \"%s\".", exp))
	}
	return h.Enigma.Validate(token)
}
