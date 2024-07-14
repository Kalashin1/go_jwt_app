package helper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("Test1234")

func CreateToken(email string, user_type string) (string, error) {

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": email,                            // Subject (user identifier)
		"iss": "todo-app",                       // Issuer
		"aud": user_type,                        // Audience (user role)
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})

	// Print information about the created token
	fmt.Printf("Token claims added: %+v\n", claims)
	tokenString, err := claims.SignedString(secretKey)

	if err != nil {
		fmt.Printf("Error in creating token: %v\n", err)
		return "", err
	}

	return tokenString, err
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	// Parse the token with the secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	// Check for verification errors
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Return the verified token
	return token, nil
}

func IsUserAdmin(token *jwt.Token) bool {
	// get token from request headers
	claims := token.Claims

	audClaims, audienceErr := claims.GetAudience()

	if audienceErr != nil {
		return false
	}

	userRole := audClaims[0]

	res := userRole == "admin"

	return res
}

func ParseRequestBody[S string, P interface{}](req *http.Request) (P, S) {
	body, err := io.ReadAll(req.Body)

	var payload P
	if err != nil {
		return payload, "Error reading request body"
	}
	err = json.Unmarshal(body, &payload)

	if err != nil {
		return payload, "Invalid JSON format in the request body"
	}

	return payload, ""
}

func HasUserPassword(toHash []byte) []byte {
	hashedPassword, hashErr := bcrypt.GenerateFromPassword(toHash, 14)
	if hashErr != nil {
		return nil
	}
	return hashedPassword
}

func CompareHashAndPassword(hashedPassword []byte, userPassword []byte, w http.ResponseWriter) {
	compareErr := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(userPassword))
	if compareErr != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}
