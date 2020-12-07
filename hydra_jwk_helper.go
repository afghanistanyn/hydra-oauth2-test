package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	pem2 "encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
)

type byteBuffer struct {
	data []byte
}

type RawJsonWebKeySet struct {
	Keys []RawJSONWebKey `json:"keys,omitempty"`
}

type RawJSONWebKey struct {
	Use string      `json:"use,omitempty"`
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	Alg string      `json:"alg,omitempty"`
	K   *byteBuffer `json:"k,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *byteBuffer `json:"d,omitempty"`
	P  *byteBuffer `json:"p,omitempty"`
	Q  *byteBuffer `json:"q,omitempty"`
	Dp *byteBuffer `json:"dp,omitempty"`
	Dq *byteBuffer `json:"dq,omitempty"`
	Qi *byteBuffer `json:"qi,omitempty"`
	// Certificates
	X5c       []string `json:"x5c,omitempty"`
	X5u       *url.URL `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

func (raw RawJSONWebKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if raw.N == nil || raw.E == nil {
		return nil, fmt.Errorf("invalid RSA key, missing n/e values")
	}
	return &rsa.PublicKey{
		N: raw.N.bigInt(),
		E: raw.E.toInt(),
	}, nil
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func (b byteBuffer) toInt() int {
	return int(b.bigInt().Int64())
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b *byteBuffer) bytes() []byte {
	// Handling nil here allows us to transparently handle nil slices when serializing.
	if b == nil {
		return nil
	}
	return b.data
}

type JwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func getRawJwk(jwkEndpoint string, kid string) (RawJSONWebKey, error) {
	var rawJwk RawJSONWebKey

	httpClient := new(http.Client)
	resp, err := httpClient.Get(jwkEndpoint)
	if err != nil {
		return rawJwk, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return rawJwk, fmt.Errorf("failed request, status: %d", resp.StatusCode)
	}

	rawJsonWebKeySet := new(RawJsonWebKeySet)
	if err = json.NewDecoder(resp.Body).Decode(rawJsonWebKeySet); err != nil {
		return rawJwk, err
	}
	for _, jwk := range rawJsonWebKeySet.Keys {
		if jwk.Kid == kid {
			return jwk, nil
		}
	}
	return rawJwk, nil
}

func convertRsaPublicKeyToPem(pubkey *rsa.PublicKey) ([]byte, error) {
	pkcsPub, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return []byte(""), err
	}
	pem := pem2.EncodeToMemory(&pem2.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkcsPub,
	})
	return pem, nil
}

func parseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem2.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
