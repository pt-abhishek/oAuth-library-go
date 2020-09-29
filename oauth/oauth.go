package oauth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/pt-abhishek/oAuth-library-go/oauth/errors"
)

const (
	headerPublic     = "X-Public"
	headerCallerID   = "X-Caller-Id"
	headerClientID   = "X-User-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
	publicKey *rsa.PublicKey
)

//AccessToken struct
type AccessToken struct {
	AccessToken string `json:"access_token"`
	ClientID    string `json:"client_id"`
	Expires     int64  `json:"expires"`
	Scope       string `json:"scope"`
	JWT         string `json:"bearer_token"`
}

//TokenRequest access token request to get token
type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`

	//For grant type client_credentials
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	//User Info for when scope contains openIDConnect
	UserID int64 `json:"user_id"`
}

//CustomClaims are the token claims
type CustomClaims struct {
	Token        string `json:"access_token"`
	IsAuthorized bool   `json:"is_authorized"`
	UserID       int64  `json:"user_id"`
	jwt.StandardClaims
}

type oauthInterface interface {
}

func init() {
	pkBytes, err := ioutil.ReadFile("/Users/abhishekverma/go/src/github.com/pt-abhishek/oAuth-library-go/oauth/keys/app.rsa.pub")
	if err != nil {
		panic(err)
	}
	publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(pkBytes)
}

//IsPublic validates if public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerPublic) == "true"
}

//AuthenticateRequest authenticates the user
func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return errors.NewBadRequestError("No request")
	}
	at, cookieErr := request.Cookie("sessionToken")
	if cookieErr != nil {
		return errors.NewUnauthorizedError("No logged in user")
	}
	t, err := ValidateToken(at.Value)
	if err != nil {
		return err
	}
	claims := t.Claims.(*CustomClaims)
	_, err = getAccessToken(claims.Token)
	if err != nil {
		return err
	}
	request.Header.Add(headerCallerID, fmt.Sprintf("%v", claims.UserID))
	return nil
}

func getAccessToken(token string) (*AccessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", token))

	if err := handleRestErrors(response); err != nil {
		return nil, err
	}
	var at AccessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error trying to parse access token")
	}
	return &at, nil
}

//GetCallerID gets caller ID from header
func GetCallerID(r *http.Request) int64 {
	callerID, err := strconv.ParseInt(r.Header.Get(headerCallerID), 10, 64)
	if err != nil {
		return -1
	}
	return callerID
}

//GetUserID gets caller ID from header
func GetUserID(r *http.Request) int64 {
	clientID, err := strconv.ParseInt(r.Header.Get(headerClientID), 10, 64)
	if err != nil {
		return -1
	}
	return clientID
}

//CreateToken creates a token
func CreateToken(t TokenRequest) (*AccessToken, *errors.RestErr) {
	response := oauthRestClient.Post("/oauth/access_token", t)
	if err := handleRestErrors(response); err != nil {
		return nil, err
	}
	//verify the JWT token if the scope contains
	var at AccessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error trying to parse access token")
	}
	if strings.Contains(t.Scope, "OPENIDCONNECT") {
		if _, err := ValidateToken(at.JWT); err != nil {
			return nil, err
		}
	}
	return &at, nil
}

func handleRestErrors(response *rest.Response) *errors.RestErr {
	if response == nil || response.Response == nil {
		return errors.NewBadRequestError("Invalid restClient response when trying to get Access token")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return errors.NewInternalServerError("Invalid error interface when trying to get access token")
		}
		return &restErr
	}
	return nil
}

//ValidateToken Validates the token
func ValidateToken(t string) (*jwt.Token, *errors.RestErr) {

	token, err := jwt.ParseWithClaims(t, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	switch err.(type) {

	case nil: // no error

		if !token.Valid { // but may still be invalid
			return nil, errors.NewUnauthorizedError("invalid token")
		}

	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)

		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, errors.NewUnauthorizedError("Token Expired, get a new one.")
		default:
			return nil, errors.NewInternalServerError("Error Parsing token")
		}

	default: // something else went wrong
		return nil, errors.NewInternalServerError("Error Parsing token")
	}
	return token, nil
}
