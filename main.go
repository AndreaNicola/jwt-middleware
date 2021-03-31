package jwtmiddleware

import (
	"errors"
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

		log.Info(jwtTokenString)

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
