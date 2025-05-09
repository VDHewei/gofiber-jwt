package server_test

import (
	"context"
	"encoding/json"
	"github.com/VDHewei/gofiber-jwt/server"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"testing"
)

func GetFiberApp() *fiber.App {
	return fiber.New(fiber.Config{})
}

func Test_New(t *testing.T) {
	var (
		app             = GetFiberApp()
		middleware      = server.New()
		ctx, cancelFunc = context.WithCancel(context.Background())
	)
	app.Use(middleware)
	app.Get("/*", func(ctx *fiber.Ctx) error {
		return ctx.JSON(fiber.Map{"code": 200, "msg": "success"})
	})
	_ = app.ShutdownWithContext(ctx)
	go app.Listen(":3000")
	defer cancelFunc()
	resp, err := http.Get("http://127.0.0.1:3000/")
	assert.Nil(t, err, "")
	assert.Equal(t, 200, resp.StatusCode)
	content, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)
	var data = make(map[string]interface{})
	err = json.Unmarshal(content, &data)
	assert.Nil(t, err)
	assert.Equal(t, float64(200), data["code"])
	assert.Equal(t, "success", data["msg"])
}
