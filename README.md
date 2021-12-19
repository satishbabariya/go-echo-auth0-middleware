# go-echo-auth0-middleware
Auth0 Middleware for go labstack/echo

# Example
```go
package main

import (
	"net/http"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	goechoauth0middleware "github.com/satishbabariya/go-echo-auth0-middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(goechoauth0middleware.Auth0WithConfig(goechoauth0middleware.Auth0Config{
		Issuer:   "https://<your tenant domain>/",
		Audience: []string{"<your api identifier>"},
	}))

	// Routes
	e.GET("/", func(c echo.Context) error {
		claims := c.Get("claims").(*validator.ValidatedClaims)
		return c.JSON(http.StatusOK, claims)
	})

	// Start server
	e.Logger.Fatal(e.Start(":3000"))
}
```