package server

import (
	"context"
	"github.com/VDHewei/gofiber-jwt/common"
	"github.com/gofiber/fiber/v2"
	"strings"
)

func AppendAuthProviderDefaultHandler(ctx *fiber.Ctx, info common.CustomClaims) {
	userCtx := ctx.UserContext()
	if userCtx == nil {
		userCtx = context.Background()
	}
	ctx.Set(UserID, info.GetUserID())
	ctx.SetUserContext(WithAuthClaims(userCtx, info))
}

func JwtHeaderLoaderDefaultHandler(ctx *fiber.Ctx) (string, bool) {
	if ctx == nil {
		return "", false
	}
	for k, values := range ctx.GetReqHeaders() {
		if strings.EqualFold(k, AuthorizationHeader) {
			return values[0], true
		}
	}
	return "", false
}

func ClaimsDefaultCreator() common.CustomClaims {
	return common.NewCustomClaims("")
}
