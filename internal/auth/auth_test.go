package auth

import (
	"errors"
	"testing"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func keyFuncWith(secret string) jwt.Keyfunc {
    return func(t *jwt.Token) (any, error) {
        if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
            return nil, errors.New("unexpected alg")
        }
        return []byte(secret), nil
    }
}

func within(d time.Duration, a, b time.Time) bool {
    if a.After(b) {
        a, b = b, a
    }
    return b.Sub(a) <= d
}

func TestMakeJWT(t *testing.T) {
	id := uuid.New()
	secret := "test-secret"
	duration := 10*time.Second
	token, err := MakeJWT(id, secret, duration)
	if err!=nil{
		t.Fatalf("MakeJWT call failed %v", err)
	}
	keyFunc := keyFuncWith(secret)
	tok, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, keyFunc)
	if err!=nil{
		t.Fatalf("Parse token failed %v", err)
	}
	resIssuer, err := tok.Claims.GetIssuer()
	if err!=nil{
		t.Fatalf("GetIssuer failed %v", err)
	}
	if  resIssuer != "chirpy"{
		t.Errorf("got %v wanted %v", resIssuer, "chirpy")
	}
	resId,err := tok.Claims.GetSubject()
	if err!=nil{
		t.Fatalf("GetSubject failed %v", err)
	}
	if resId!=id.String(){
		t.Errorf("got %v wanted %v", resId, id.String()) 
	}
	resIssuedAt, err := tok.Claims.GetIssuedAt()
	if err!=nil{
		t.Fatalf("GetIssuedAt failed %v", err)
	}
	now := time.Now().UTC()
	if !within(2*time.Second, now, resIssuedAt.Time){
		t.Errorf("got %v wanted %v", now, resIssuedAt.Time) 
	}
	resExpiredAt, err := tok.Claims.GetExpirationTime()
	if err!=nil{
		t.Fatalf("GetExpirationTime failed %v", err)
	}
	wantedExp := now.Add(duration)
	if !within(2*time.Second, wantedExp, resExpiredAt.Time){
		t.Errorf("got %v wanted %v", wantedExp, resExpiredAt.Time) 
	}
	if tok.Method.Alg() != "HS256"{
		t.Errorf("got %v wanted %v", tok.Method.Alg(), "HS256") 
	}
}

func TestValidateJWT(t *testing.T) {
	id := uuid.New()
	secret := "test-secret"
	duration := 10*time.Second
	token, err := MakeJWT(id, secret, duration)
	if err!=nil{
		t.Fatalf("MakeJWT call failed %v", err)
	}
	_, err = ValidateJWT(token, "test-secret")
	if err!=nil{
		t.Errorf("got %v wanted %v", err, nil) 
	}
}

func TestExpiredToken(t *testing.T) {
	id := uuid.New()
	secret := "test-secret"
	duration := -1*time.Second
	token, err := MakeJWT(id, secret, duration)
	if err!=nil{
		t.Fatalf("MakeJWT call failed %v", err)
	}
	_, err = ValidateJWT(token, "test-secret")
	if err==nil{
		t.Fatalf("Validate token failed %v", err)
	}
}

func TestWrongSecret(t *testing.T) {
	id := uuid.New()
	secret := "test-secret"
	duration := 1*time.Minute
	token, err := MakeJWT(id, secret, duration)
	if err!=nil{
		t.Fatalf("MakeJWT call failed %v", err)
	}
	_, err = ValidateJWT(token, "wrong-secret")
	if err==nil{
		t.Fatalf("Validate token failed %v", err)
	}
}
