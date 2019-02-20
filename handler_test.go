/*
Copyright (c) 2017 Bitnami

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"gopkg.in/mgo.v2/bson"
)

// Set the JWT signingKey to a test value
func init() {
	key := "test"
	signingKey = &key
}

var u = &UserModel{
	ID:    bson.NewObjectId(),
	Name:  "Test User",
	Email: "test@example.com",
}

var validClaims = userClaims{
	UserModel: u,
	StandardClaims: jwt.StandardClaims{
		ExpiresAt: tokenExpiration().Unix(),
		Issuer:    "test",
	},
}

var expiredClaims = userClaims{
	UserModel: u,
	StandardClaims: jwt.StandardClaims{
		ExpiresAt: time.Now().Add(-time.Hour * 2).Unix(),
		Issuer:    "test",
	},
}

func signedTokenFromClaims(claims userClaims, key string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(key))
	return signedToken
}

func TestVerify(t *testing.T) {
	t.Run("no cookie/session", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/verify", nil)
		Verify(w, r)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "session not found")
	})

	tests := []struct {
		name            string
		claims          userClaims
		signingKey      string
		expectedStatus  int
		containsMessage string
	}{
		{"valid token", validClaims, *signingKey, http.StatusOK, ""},
		{"invalid/expired token", expiredClaims, *signingKey, http.StatusUnauthorized, "expired"},
		{"invalid signature", expiredClaims, "invalid", http.StatusUnauthorized, "signature is invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/verify", nil)

			signedToken := signedTokenFromClaims(tt.claims, tt.signingKey)
			jwtCookie := &http.Cookie{Name: "ka_auth", Value: signedToken, Path: "/", Expires: tokenExpiration(), HttpOnly: true}
			r.AddCookie(jwtCookie)

			Verify(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.containsMessage)
		})
	}
}

func TestLogout(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/logout", nil)
	Logout(w, r)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.True(t, cookie.Expires.Before(time.Now()))
}
