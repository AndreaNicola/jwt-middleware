package jwtmiddleware

import (
	"errors"
	"fmt"
	src "github.com/AndreaNicola/strapi-rest-client"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strings"
	"time"
)

var secret []byte

func init() {

	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if jwtAccessSecret == "" {
		panic("JWT_ACCESS_SECRET env variable is not set")
	}

	secret = []byte(jwtAccessSecret)

}

func tokenValidationAndExtraction(context *gin.Context) error {

	jwtTokenString, err := extractToken(context)

	if err != nil {
		return err
	}

	jwtToken, err := jwt.Parse(*jwtTokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil

	})

	if err != nil {
		return err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)

	if !(ok || jwtToken.Valid) {
		return errors.New("token is not valid")
	}

	// is it useless? i don't know...
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return errors.New("token expired")
	}

	if ok && jwtToken.Valid {

		if context.Keys == nil {
			context.Keys = make(map[string]interface{})
		}

		context.Keys["userId"] = claims["id"]

	}

	return nil

}

func DummyMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
	}
}

func JwtMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {

		err := tokenValidationAndExtraction(context)

		if err != nil {
			context.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		context.Next()

	}
}

func extractToken(context *gin.Context) (*string, error) {

	bearerToken := context.GetHeader("Authorization")

	if bearerToken == "" {
		return nil, errors.New("no bearer token")
	}

	strArr := strings.Split(bearerToken, " ")

	if len(strArr) != 2 {
		return nil, errors.New("no bearer token")
	}

	return &strArr[1], nil

}

func StrapiCheckRoleMiddleware(src src.StrapiRestClient, roles ...string) func(ctx *gin.Context) {

	return func(ctx *gin.Context) {


		userId := ctx.Keys["userId"].(float64)
		currentUser := src.GetUser(int(userId))

		hasRole := false
		for _, e := range roles {

			hasRole = hasRole || e == currentUser.Role.Type

		}

		if !hasRole {
			ctx.AbortWithStatusJSON(403, &gin.H{
				"error": "forbidden",
			})
			return
		}

		ctx.Next()

	}

}
