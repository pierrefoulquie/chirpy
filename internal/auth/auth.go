package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error){
	if hashedPassowrd, err := bcrypt.GenerateFromPassword([]byte(password), 0);err!=nil{
		fmt.Println("Encryption failed:", err)
		return "", err
	}else{
		return string(hashedPassowrd), nil
	}
}

func CheckPasswordHash(hash, password string) error{
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(hash))
}

func MakeJWT(userID uuid.UUID, tokenSecret string) (string, error){
	claim := jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		Subject: userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	signed, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signed, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error){
	keyFunc := func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(tokenSecret), nil
	}	
	tok, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, keyFunc)
	if err != nil {
		return uuid.UUID{}, err
	}
	sub, err := tok.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	id, err := uuid.Parse(sub)
	if err != nil {
		return uuid.UUID{}, err
	}
	return id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", fmt.Errorf("missing Authorization header")
    }
    const prefix = "Bearer"
    if !strings.HasPrefix(authHeader, prefix) {
        return "", fmt.Errorf("invalid auth header")
    }
    token := strings.TrimSpace(authHeader[len(prefix):])
    if token == "" {
        return "", fmt.Errorf("empty bearer token")
    }
    return token, nil
}

func MakeRefreshToken() (string, error) {
	tok := make([]byte, 32)
	rand.Read(tok)
	tokStr := hex.EncodeToString(tok)
	return tokStr, nil
}

func GetAPIKey(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", fmt.Errorf("missing Authorization header")
    }
    const prefix = "ApiKey"
    if !strings.HasPrefix(authHeader, prefix) {
        return "", fmt.Errorf("invalid auth header")
    }
    token := strings.TrimSpace(authHeader[len(prefix):])
    if token == "" {
        return "", fmt.Errorf("empty api key")
    }
    return token, nil
}
