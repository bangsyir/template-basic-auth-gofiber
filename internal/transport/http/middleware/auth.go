package middleware

import (
	"go-auth/internal/domain/user"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuth(secret string, userSerivce *user.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. try to get access token from cookie
		accessToken := c.Cookies("access_token")
		if accessToken == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing authentication token",
			})
		}

		// 2. Parse and validate JWT
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid signing method")
			}
			return []byte(secret), nil
		})
		// 3. If invalid. try refresh token
		if err != nil || !token.Valid {
			// call the service method correctly
			userID, refreshErr := userSerivce.RefreshToken(c.Context(), c)
			if refreshErr != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Session expired, please login again",
				})

			}
			// Stored user ID in context after successful refresh
			c.Locals("userID", userID)
			return c.Next()
		}
		// 4. extract claims from valid token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}
		// convert user ID to uint properly
		userID, ok := claims["user_id"].(float64)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid user ID in token",
			})
		}
		// 5. Store user ID in context
		c.Locals("userID", uint(userID))
		return c.Next()

	}
}
