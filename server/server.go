package server

import (
	"fmt"
	"github.com/VDHewei/gofiber-jwt/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

type (
	config struct {
		Secret              string
		Algorithm           string
		AuthorizationHeader string
		Unauthorized        fiber.Handler
		ClaimsCreator       ClaimsCreator
		AuthResultSetter    AppendAuthProvider
		JwtHeaderLoader     JwtHeaderLoader
		AlgoSecretManger    AlgoSecretManger
	}

	AlgoSecretManger interface {
		GetAlgos() []string
		GetSecret(algo string) string
	}

	Option             func(*config)
	JwtHeaderLoader    func(c *fiber.Ctx) (string, bool)
	AppendAuthProvider func(c *fiber.Ctx, claims common.CustomClaims)
	ClaimsCreator      func() common.CustomClaims
)

func (c *config) apply(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}

func WithSecret(secret string) Option {
	return func(c *config) {
		c.Secret = secret
	}
}

func WithUnauthorizedHandler(f fiber.Handler) Option {
	return func(c *config) {
		c.Unauthorized = f
	}
}

func WithAlgorithm(algo string) Option {
	return func(c *config) {
		c.Algorithm = algo
	}
}

func WithClaimsCreator(h ClaimsCreator) Option {
	return func(c *config) {
		c.ClaimsCreator = h
	}
}

func WithAuthResultSetter(h AppendAuthProvider) Option {
	return func(c *config) {
		c.AuthResultSetter = h
	}
}

func WithJwtHeaderLoader(h JwtHeaderLoader) Option {
	return func(c *config) {
		c.JwtHeaderLoader = h
	}
}

func WithAuthorizationHeader(header string) Option {
	return func(c *config) {
		c.AuthorizationHeader = header
	}
}

type Parser struct {
	config *config
}

func (p *Parser) Validate(tokenStr string) (common.CustomClaims, error) {
	return p.Parse(tokenStr)
}

func (p *Parser) Parse(tokenStr string) (common.CustomClaims, error) {
	var (
		opts       = p.GetJWTParseOptions()
		c          = p.config.ClaimsCreator()
		token, err = jwt.ParseWithClaims(tokenStr, c, p.GetJWTKeyFunc(), opts...)
	)
	if claims, matched := token.Claims.(common.CustomClaims); matched && token.Valid {
		return claims, nil
	}
	return nil, err
}

func (p *Parser) GetToken(ctx *fiber.Ctx) string {
	if p.config.JwtHeaderLoader != nil {
		if token, ok := p.config.JwtHeaderLoader(ctx); ok {
			return token
		}
		return ""
	}
	if h := p.config.AuthorizationHeader; h != "" {
		headers := ctx.GetReqHeaders()
		for k, values := range headers {
			if strings.EqualFold(k, h) {
				return values[0]
			}
		}
	}
	return ""
}

func (p *Parser) GetUnauthorizedNext() fiber.Handler {
	if p.config.Unauthorized == nil {
		return nil
	}
	return p.config.Unauthorized
}

func (p *Parser) SetAuthorized(ctx *fiber.Ctx, info common.CustomClaims) {
	if h := p.config.AuthResultSetter; h != nil {
		h(ctx, info)
		return
	}
	AppendAuthProviderDefaultHandler(ctx, info)
}

func (p *Parser) GetJWTKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var algo = token.Method.Alg()
		if p.config.Secret != "" &&
			strings.EqualFold(algo, p.config.Algorithm) {
			return []byte(p.config.Secret), nil
		}
		if p.config.AlgoSecretManger != nil {
			secret := p.config.AlgoSecretManger.GetSecret(token.Method.Alg())
			return []byte(secret), nil
		}
		return nil, fmt.Errorf("algo(%s) key not supplied", algo)
	}
}

func (p *Parser) GetJWTParseOptions() []jwt.ParserOption {
	return []jwt.ParserOption{
		jwt.WithValidMethods(p.getMethods()),
	}
}

func (p *Parser) getMethods() []string {
	if p.config.Algorithm != "" {
		return []string{p.config.Algorithm}
	}
	if p.config.AlgoSecretManger != nil {
		return p.config.AlgoSecretManger.GetAlgos()
	}
	return []string{}
}

func NewParser(opts ...Option) *Parser {
	var c = newDefaultConfig()
	c.apply(opts...)
	return &Parser{
		config: c,
	}
}

func newDefaultConfig() *config {
	return &config{
		Secret:              "",
		Algorithm:           "",
		Unauthorized:        nil,
		ClaimsCreator:       ClaimsDefaultCreator,
		AuthorizationHeader: AuthorizationHeader,
		JwtHeaderLoader:     JwtHeaderLoaderDefaultHandler,
		AuthResultSetter:    AppendAuthProviderDefaultHandler,
	}
}

func New(opts ...Option) fiber.Handler {
	parser := NewParser(opts...)
	return func(ctx *fiber.Ctx) error {
		var (
			token   = parser.GetToken(ctx)
			handler = parser.GetUnauthorizedNext()
		)
		if token == "" && handler != nil {
			return handler(ctx)
		}
		if token != "" {
			info, err := parser.Validate(token)
			if err != nil {
				return err
			}
			parser.SetAuthorized(ctx, info)
		}
		return ctx.Next()
	}
}
