package main

import (
	"crypto/tls"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"net/http"
	"os"
)

var (
	// DefaultKeyAuthConfig is the default KeyAuth middleware config.
	CookieKeyAuthConfig = middleware.KeyAuthConfig{
		Skipper:   defaultSkipper,
		KeyLookup: "cookie:token",
		Validator: validator,
	}

	ciamDomain = os.Getenv("CIAM_DOMAIN")
)

func defaultSkipper(c echo.Context) bool {
	return false
}

func validator(key string, c echo.Context) bool {
	c.Logger().Debug("Key " + key)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	sessionRequest, _ := http.NewRequest(echo.GET, "https://"+ciamDomain+"/ui/api/session/verify", nil)
	cookie := http.Cookie{Name: "token", Value: key, Domain: ciamDomain, Secure: true, HttpOnly: true}
	sessionRequest.AddCookie(&cookie)
	resp, err := client.Do(sessionRequest)
	if resp != nil && resp.StatusCode == 200 {
		sessionDetails, _ := http.NewRequest(echo.GET, "https://"+ciamDomain+"/ui/api/session", nil)
		sessionDetails.AddCookie(&cookie)
		resp, err = client.Do(sessionDetails)
		if resp != nil {
			htmlData, _ := ioutil.ReadAll(resp.Body)
			c.Logger().Debug(string(htmlData))
		}
	}

	if err != nil {
		c.Logger().Debug(err)
	}
	return err == nil
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
