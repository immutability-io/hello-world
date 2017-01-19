package main

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"net/http"
)

var (
	// DefaultKeyAuthConfig is the default KeyAuth middleware config.
	CookieKeyAuthConfig = middleware.KeyAuthConfig{
		Skipper:   defaultSkipper,
		KeyLookup: "cookie:token",
		Validator: validator,
	}
)

func defaultSkipper(c echo.Context) bool {
	return false
}

func validator(key string, c echo.Context) bool {
	c.Logger().Debug("Key " + key)
	return key == "valid-key"
}

func main() {
	// Echo instance
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)
	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.KeyAuthWithConfig(CookieKeyAuthConfig))
	// Route => handler
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!\n")
	})

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}
