package jwtmiddleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"
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

	jwtToken, err := jwt.Parse(* jwtTokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil

	})

	if err != nil {
		return err
	}

	if _, ok := jwtToken.Claims.(jwt.Claims); !(ok || jwtToken.Valid) {
		return errors.New("token is not valid")
	}

	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		logrus.Info(claims["data"])
	}

	return nil

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

func RoleBasedJwtMiddleware(role []string) gin.HandlerFunc {
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
