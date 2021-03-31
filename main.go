package jwtmiddleware

import (
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

		jwtTokenString := extractToken(context)

		defer func(){
			if r := recover(); r != nil {
				context.AbortWithStatusJSON(http.StatusUnauthorized, r)
				return
			}
		}()

		log.Info(jwtTokenString)


		context.Next()
	}
}

func extractToken(context *gin.Context) string {
	bearerToken := context.GetHeader("Authorization")

	if bearerToken == "" {
		panic("no bearer token")
	}

	strArr := strings.Split(bearerToken, " ")

	if len(strArr) != 2 {
		panic("no bearer token")
	}

	return strArr[1]

}

func verifyToken() {

}
