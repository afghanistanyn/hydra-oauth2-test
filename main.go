package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ory/x/cmdx"
	"github.com/ory/x/randx"
	//"github.com/square/go-jose/jwt"
	"golang.org/x/oauth2"
	"net/http"
	"strconv"
	"strings"
)

// oauth2 hydra
const IndexHtml = `
<html>
	<body>
		<a href="/wework/login/">log in with wework</a>
	</body>
</html>
`

// http://localhost:4444/.well-known/openid-configuration
var hydraAuthEndpint = oauth2.Endpoint{
	AuthURL:  "http://127.0.0.1:4444/oauth2/auth",
	TokenURL: "http://127.0.0.1:4444/oauth2/token",
}
var hydraUserInfoEndpint = "http://127.0.0.1:4444/userinfo"
var hydraJwkEndpoint = "http://127.0.0.1:4444/.well-known/jwks.json"

var hydraOauthConfig = &oauth2.Config{
	ClientID:     "auth-code-client",
	ClientSecret: "secret",
	Endpoint:     hydraAuthEndpint,
	RedirectURL:  "http://localhost:5556/callback",
	Scopes:       []string{"offline", "openid"},
}

func main() {
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/wework/login/", LoginHandler)
	http.HandleFunc("/callback", CallbackHandler)
	fmt.Println(http.ListenAndServe(":5556", nil))

}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, IndexHtml)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	state, err := randx.RuneSequence(24, randx.AlphaLower)
	cmdx.Must(err, "Could not generate random state: %s", err)

	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	cmdx.Must(err, "Could not generate random state: %s", err)

	authCodeURL := hydraOauthConfig.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		//oauth2.SetAuthURLParam("prompt", strings.Join(prompt, "+")),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(0)),
	)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {

	error := r.FormValue("error")
	if error != "" {
		fmt.Fprintf(w, "error: %s\n\nerror_description: %s\n\nerror_hint: %s", error, r.FormValue("error_description"), r.FormValue("error_hint"))
		return
	}

	code := r.FormValue("code")
	opt := oauth2.SetAuthURLParam("token_endpoint_auth_method", "client_secret_post")
	token, err := hydraOauthConfig.Exchange(oauth2.NoContext, code, opt)
	if err != nil {
		fmt.Printf("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	fmt.Printf("exchange token from hydra sucessful: %v\n", token)

	//get user info from hydra userinfo endpoint with access_token
	//resp, err := http.Get(hydraUserInfoEndpint + "?access_token=" + token.AccessToken)
	//defer resp.Body.Close()
	//contents, err := ioutil.ReadAll(resp.Body)
	//fmt.Printf("userinfo: %s\n", contents)

	// use jwt user info
	jws := fmt.Sprintf("%s", token.Extra("id_token"))
	fmt.Printf("jwt: %s\n", jws)

	jwsParts := strings.Split(jws, ".")
	jwt_header, err := base64.RawURLEncoding.DecodeString(jwsParts[0])
	if err != nil {
		fmt.Println(fmt.Errorf("decode jwt header error: %s\n", err))
		return
	}

	jwt_payload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
	if err != nil {
		fmt.Printf("decode jwt payload error: %s\n", err)
	}
	fmt.Printf("jwt_payload: %s\n", jwt_payload)

	//jwt_sign := jwkParts[2]

	//get kid from jwt_header
	jwtHeader := new(JwtHeader)
	json.Unmarshal(jwt_header, &jwtHeader)
	kid := jwtHeader.Kid
	//kid := "public:f05725b9-e363-4fac-92c7-a42c5448c52f"

	rawJwk, err := getRawJwk(hydraJwkEndpoint, kid)
	if err != nil {
		fmt.Println(fmt.Errorf("getRawJwk by kid error", err))
		return
	}
	rsaPubkey, err := rawJwk.rsaPublicKey()
	if err != nil {
		fmt.Println(fmt.Errorf("generate rsa public key error: ", err))
	}

	err = verifyToken(jws, rsaPubkey)
	if err != nil {
		fmt.Println(fmt.Errorf("token is invalid, error: %s", err))
	}

}
