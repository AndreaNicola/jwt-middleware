package jwtmiddleware

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

var secret []byte

func init() {

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

		jwt.Parse(* jwtTokenString, func(token *jwt.Token) (interface{}, error) {

			log.Info(token)

			return nil, nil
		})

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
