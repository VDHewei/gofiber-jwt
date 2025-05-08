package common

import "github.com/golang-jwt/jwt/v5"

type (
	UserClaims struct {
		jwt.RegisteredClaims
		UserID string `json:"user_id"`
	}

	CustomClaims interface {
		jwt.Claims
		GetUserID() string
	}
)

func (c *UserClaims) SetUserID(userID string) {
	c.UserID = userID
}

func (c *UserClaims) GetUserID() string {
	return c.UserID
}

func NewCustomClaims(uid string) CustomClaims {
	return &UserClaims{
		UserID:           uid,
		RegisteredClaims: jwt.RegisteredClaims{},
	}
}
