package jwtmiddleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"strings"
)

var secret []byte

func init() {
	secret = []byte(os.Getenv("JWT_ACCESS_SECRET"))
}

func JwtMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()
	}
}

func RoleBasedJwtMiddleware(role []string) gin.HandlerFunc {
	return func(context *gin.Context) {

		jwtTokenString, err := extractToken(context)

		if err != nil {
			context.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		jwtToken, err := jwt.Parse(* jwtTokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return secret, nil

		})

		if err != nil {
			context.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		if _, ok := jwtToken.Claims.(jwt.Claims); !(ok || jwtToken.Valid) {
			context.AbortWithStatusJSON(http.StatusUnauthorized, errors.New("token is not valid"))
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

func verifyToken() {

}
