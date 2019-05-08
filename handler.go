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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kubeapps/common/response"
	"golang.org/x/oauth2"
	"gopkg.in/mgo.v2/bson"
)

const userCollection = "users"

type oauthUserInfo struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string
	ID        int
}

// UserModel holds the user information in the claim
type UserModel struct {
	ID        bson.ObjectId `json:"id" bson:"_id,omitempty"`
	Name      string        `json:"name"`
	Email     string        `json:"email"`
	BitnamiID int           `json:"bitnami_id" bson:"bitnami_id"`
}

type userClaims struct {
	*UserModel
	jwt.StandardClaims
}

// InitiateOAuth initiatates an OAuth request
func InitiateOAuth(w http.ResponseWriter, r *http.Request) {
	oauthConfig := getOauthConfig(r.Host)
	state := randomStr()
	session, _ := sessionStore.Get(r, "ka_sess")
	session.Values["state"] = state
	session.Save(r, w)

	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

// BitnamiCallback processes the OAuth callback from Bitnami
func BitnamiCallback(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "ka_sess")
	if err != nil {
		response.NewErrorResponse(http.StatusBadRequest, "invalid session").Write(w)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		response.NewErrorResponse(http.StatusBadRequest, "no state match - possible CSRF or cookies not enabled").Write(w)
		return
	}

	oauthConfig := getOauthConfig(r.Host)
	tkn, err := oauthConfig.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		response.NewErrorResponse(http.StatusBadRequest, "unable to get access token").Write(w)
		return
	}

	if !tkn.Valid() {
		response.NewErrorResponse(http.StatusInternalServerError, "invalid access token retrieved").Write(w)
		return
	}

	u, err := getUserInfo(tkn)
	if err != nil {
		response.NewErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error retrieving user: %s", err.Error())).Write(w)
		return
	}

	db, closer := dbSession.DB()
	defer closer()

	if _, err := db.C(userCollection).Upsert(bson.M{"email": u.Email}, u); err != nil {
		response.NewErrorResponse(http.StatusInternalServerError, "unable to update user").Write(w)
		return
	}

	// Fetch from DB to get ID
	if err := db.C(userCollection).Find(bson.M{"email": u.Email}).One(u); err != nil {
		response.NewErrorResponse(http.StatusInternalServerError, "unable to get user ID").Write(w)
		return
	}

	claims := userClaims{
		UserModel: u,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: tokenExpiration().Unix(),
			Issuer:    r.Host,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(*signingKey))
	jwtCookie := http.Cookie{Name: "ka_auth", Value: signedToken, Path: "/", Expires: tokenExpiration(), HttpOnly: true}

	jsonClaims, err := json.Marshal(claims)
	if err != nil {
		response.NewErrorResponse(http.StatusInternalServerError, "error marshalling claims").Write(w)
		return
	}
	claimsCookie := http.Cookie{Name: "ka_claims", Value: base64.StdEncoding.EncodeToString(jsonClaims), Path: "/"}

	http.SetCookie(w, &jwtCookie)
	http.SetCookie(w, &claimsCookie)

	http.Redirect(w, r, "/", http.StatusFound)
}

// Verify implements a check to see if the user is logged in, it returns
// Unauthorized if logged in, Success otherwise
func Verify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("ka_auth")
	if err != nil {
		response.NewErrorResponse(http.StatusUnauthorized, "session not found").Write(w)
		return
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(*signingKey), nil
	})
	if err != nil {
		response.NewErrorResponse(http.StatusUnauthorized, err.Error()).Write(w)
		return
	}

	if _, ok := token.Claims.(*userClaims); ok && token.Valid {
		w.WriteHeader(http.StatusOK)
	} else {
		response.NewErrorResponse(http.StatusUnauthorized, "invalid token").Write(w)
	}
}

// Logout clears the JWT token cookie
func Logout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{Name: "ka_auth", Value: "", Path: "/", Expires: time.Unix(1, 0)}
	http.SetCookie(w, &cookie)
}

func getUserInfo(tkn *oauth2.Token) (*UserModel, error) {
	auth := fmt.Sprintf("%s %s", strings.Title(tkn.TokenType), tkn.AccessToken)
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://bitnami.com/account/me.json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("User-Agent", "oauth2-bitnami")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response for user info request: %d", res.StatusCode)
	}

	var info oauthUserInfo
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return nil, err
	}

	if info.Email == "" {
		return nil, fmt.Errorf("unable to retrieve user email")
	}

	return &UserModel{Name: fmt.Sprintf("%s %s", info.FirstName, info.LastName), Email: info.Email, BitnamiID: info.ID}, nil
}

func getOauthConfig(host string) *oauth2.Config {
	// TODO: make this configuration extensible/configurable
	bitnamiEndpoint := oauth2.Endpoint{
		AuthURL:  "https://bitnami.com/oauth/authorize",
		TokenURL: "https://bitnami.com/oauth/token",
	}
	return &oauth2.Config{
		ClientID:     *oauthClientID,
		ClientSecret: *oauthClientSecret,
		Endpoint:     bitnamiEndpoint,
		// Note the `/auth` prefix is expected to be handled by the API gateway
		RedirectURL: "http://" + host + "/auth/bitnami/callback",
	}
}

func randomStr() string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func tokenExpiration() time.Time {
	return time.Now().Add(time.Hour * 2)
}
