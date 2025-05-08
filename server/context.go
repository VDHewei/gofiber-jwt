package server

import (
	"context"
	"github.com/VDHewei/gofiber-jwt/common"
)

type authCtxKey struct{}

const (
	UserID              = `jwt::uid`
	AuthorizationHeader = `Authorization`
)

func WithAuthClaims(ctx context.Context, c common.CustomClaims) context.Context {
	return context.WithValue(ctx, authCtxKey{}, c)
}

func GetAuthClaimsByCtx(ctx context.Context) common.CustomClaims {
	if v := ctx.Value(authCtxKey{}); v != nil {
		return v.(common.CustomClaims)
	}
	return nil
}
