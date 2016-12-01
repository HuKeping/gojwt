package jwt

import (
	"strings"
	"time"

	"github.com/HuKeping/gojwt/jws"
	"github.com/HuKeping/gojwt/utils"
)

var defaultHeader = &jws.Header{Algorithm: "RS256", Typ: "JWT"}

// Config is the configuration for using JWT to fetch tokens,
// commonly known as "two-legged OAuth 2.0".
type Config struct {
	// Email is the OAuth client identifier used when communicating with
	// the configured OAuth provider.
	Email string

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey []byte

	// PrivateKeyID contains an optional hint indicating which key is being
	// used.
	PrivateKeyID string

	// Subject is the optional user to impersonate.
	Subject string

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string

	// TokenURL is the endpoint required to complete the 2-legged JWT flow.
	TokenURL string

	// Expires optionally specifies how long the token is valid for.
	Expires time.Duration

	// AuthURL is the endpoint where we do the authentication.
	AuthURL string
}

func (c *Config) Token() (string, error) {
	pk, err := utils.ParseKey(c.PrivateKey)
	claimSet := &jws.ClaimSet{
		Iss:   c.Email,
		Scope: strings.Join(c.Scopes, " "),
		Aud:   c.TokenURL,
	}

	if subject := c.Subject; subject != "" {
		claimSet.Sub = subject
		// prn is the old name of sub. Keep setting it
		// to be compatible with legacy OAuth 2.0 providers.
		claimSet.Prn = subject
	}
	if t := c.Expires; t > 0 {
		claimSet.Exp = time.Now().Add(t).Unix()
	}
	payload, err := jws.Encode(defaultHeader, claimSet, pk)
	if err != nil {
		return "", err
	}

	return payload, nil
}

func GenerateJWT() (string, error) {

	conf := &Config{
		PrivateKey: testPriKey,
		AuthURL:    testAuthURL,
	}

	return conf.Token()
}

var testPriKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqNt5+U61Ws6/Qg54kYp+LkscfcOLQ7aeVm7wAhNIlsNk9Jeh
hz5ymumgRZidxsUULcL3jPnEFbm9wCoyEuznSaXkAOXzq6ZwuXYL+Zfw25meUh68
wJvSYGJq8O1I9XcnkOo6T62uAoRez2DiHKHk6eHljkic87WUMn7ZwS1UYEyGF119
ZFWVX1lRbE9hUJO3ovRsP1J7JclUHR2cWGvfEgJrKEOWGW9yNdU5NSx7Akuj8vae
rS973clvayYqKjbtkYTv1sIaokrbXf8U2p8CUZQ+SFhN9glNyCOFLWmWa2A3opkX
pFVe86sIEwQMzbJmrWYQ9aOhPS2fQyRYSsMA1wIDAQABAoIBAG6mtD1dCJajGM3u
sa+d86XebqMzOtV6nDPDqt+RR2YUUNm/a4g2sd817WLt6aZRizGZq6LkIUyjVObS
P9ILEF1AqjK0fYMkJIZEBwDeQmWFOyxRHBuTgL7Mf4u10rOYC4N5GhEQnRDlMUPw
FvvwUxO4hjdA+ijx+lVErulaDQq0yj5mL4LWu4cHm576OufzgHOIp6fQtfRVJIXD
W2ginblgYFLd+PPiM1RMPR/Pj63VWXWBn1VwLAxWN889E4VG2medl0taQgkNQ3/W
0J04KiTXPrtcUBy2AGoHikvN7gG7Up2IwRRbsXkUdhQNZ/HnIQlkFfteiqqt9VNR
Nsi31nECgYEA0qE+96TvYf8jeZsqrl8YQAvjXWrNA05eKZlT6cm6XpyXq22v9Cgn
2KXEhRwHZF2dQ2C+1PvboeTUbpdPX1nY2shY59L7+t68F/jxotcjx0yL+ZC742Fy
bWsc8Us0Ir2DD5g/+0F+LRLFJKSfJPdLzEkvwuYnlm6RcFlbxIxW6h0CgYEAzTrE
6ulEhN0fKeJY/UaK/8GlLllXc2Z5t7mRicN1s782l5qi0n1R57VJw/Ezx4JN1mcQ
4axe9zzjAA5JfSDfyTyNedP1KOmCaKmBqGa9JppxGcVQpMDg8+QvYnJ8o5JXEXSE
TOnpY4RTEA1RGnA5KbbJ7R1MiHUGXC9nizVHxIMCgYB8cu1DYN5XpmoNddK4CFPJ
s7x4+5t6MpmMNp3P6nMFZ7xte3eU6QzyAq+kfjUX5f//SXA3Y0AX3Z5uYVRyYCGy
0uFEx/I9/dBg0aPjtP3cyauCnzOEW5VCdSE6qFZ7mEGRu0FCcSXd99MnnWSycLMG
Vs+zdk05osan/QQtk0XfOQKBgDfkIWy4SmjEr5AAjKutYn10hz+wJRjQd6WJbBFQ
oeVp1bxD6MPaTUwFGym5rphO7FPPjdFn2BUNB+Uj/u+M3GU5kG31Q3b44QMP5reu
AyVYOiUCj4vO23SQWDc/ZqJFYGDokn8/1Me9acGdXtEMbwTlOujQad9fv3OrlU9c
G0dxAoGAHcntflD6UvQ5/PYOirNJL1GhSspF7u72NrsYjaoZls83uIqucJiB5hMH
Ovq1TJbl0DwDBOyMmt5gZraPQB0P5/5GvnxqGlIAKIwi2VuQ2XHpSBE8Pg5Pveb8
sgFLFnwL5+JyqOP65AV3Eh5b4BJc6kqKz4gVmKLBQeo6lE13sNs=
-----END RSA PRIVATE KEY-----`)

var testAuthURL = string("localhost:12345")
