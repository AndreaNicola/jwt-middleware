package jwtmiddleware

import "github.com/gin-gonic/gin"

func JwtMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Next()
	}
}
