package main

import (
	"errors"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"net/http"
)

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
	e.Use(CookieAuth(validator))
	// Route => handler
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!\n")
	})

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

type (
	// CookieAuthConfig defines the config for CookieAuth middleware.
	CookieAuthConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper

		// KeyLookup is a string in the form of "<source>:<name>" that is used
		// to extract key from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		KeyLookup string `json:"key_lookup"`

		// AuthScheme to be used in the Authorization header.
		// Optional. Default value "Bearer".
		AuthScheme string

		// Validator is a function to validate key.
		// Required.
		Validator CookieAuthValidator
	}

	// CookieAuthValidator defines a function to validate CookieAuth credentials.
	CookieAuthValidator func(string, echo.Context) bool

	keyExtractor func(echo.Context) (string, error)
)

func defaultSkipper(c echo.Context) bool {
	return false
}

var (
	// DefaultCookieAuthConfig is the default CookieAuth middleware config.
	DefaultCookieAuthConfig = CookieAuthConfig{
		Skipper:    defaultSkipper,
		KeyLookup:  "token",
		AuthScheme: "Bearer",
	}
)

// CookieAuth returns an CookieAuth middleware.
//
// For valid key it calls the next handler.
// For invalid key, it sends "401 - Unauthorized" response.
// For missing key, it sends "400 - Bad Request" response.
func CookieAuth(fn CookieAuthValidator) echo.MiddlewareFunc {
	c := DefaultCookieAuthConfig
	c.Validator = fn
	return CookieAuthWithConfig(c)
}

// CookieAuthWithConfig returns an CookieAuth middleware with config.
// See `CookieAuth()`.
func CookieAuthWithConfig(config CookieAuthConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultCookieAuthConfig.Skipper
	}
	// Defaults
	if config.AuthScheme == "" {
		config.AuthScheme = DefaultCookieAuthConfig.AuthScheme
	}
	if config.KeyLookup == "" {
		config.KeyLookup = DefaultCookieAuthConfig.KeyLookup
	}
	if config.Validator == nil {
		panic("key-auth middleware requires a validator function")
	}

	// Initialize
	extractor := keyFromCookie(DefaultCookieAuthConfig.KeyLookup)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			// Extract and verify key
			key, err := extractor(c)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
			if config.Validator(key, c) {
				return next(c)
			}

			return echo.ErrUnauthorized
		}
	}
}

// keyFromHeader returns a `keyExtractor` that extracts key from the request header.
func keyFromHeader(header string, authScheme string) keyExtractor {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		if auth == "" {
			return "", errors.New("Missing key in request header")
		}
		if header == echo.HeaderAuthorization {
			l := len(authScheme)
			if len(auth) > l+1 && auth[:l] == authScheme {
				return auth[l+1:], nil
			}
			return "", errors.New("Invalid key in the request header")
		}
		return auth, nil
	}
}

// keyFromQuery returns a `keyExtractor` that extracts key from the query string.
func keyFromQuery(param string) keyExtractor {
	return func(c echo.Context) (string, error) {
		key := c.QueryParam(param)
		if key == "" {
			return "", errors.New("Missing key in the query string")
		}
		return key, nil
	}
}

func keyFromCookie(param string) keyExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie("username")
		if cookie == nil {
			return "", errors.New("Missing cookie")
		}
		if cookie.Value == "" {
			return "", errors.New("Missing key in the cookie")
		}
		return cookie.Value, nil
	}
}
