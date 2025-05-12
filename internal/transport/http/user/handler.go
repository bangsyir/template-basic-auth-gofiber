package http

import (
	"go-auth/internal/domain/user"

	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	service *user.Service
}

func NewUserHandler(service *user.Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.ErrBadRequest
	}
	if err := h.service.Register(c.Context(), req.Username, req.Email, req.Password); err != nil {
		return fiber.NewError(fiber.StatusConflict, "register failed")
	}
	return c.SendStatus(fiber.StatusCreated)
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.ErrBadRequest
	}

	user, accessToken, refreshToken, err := h.service.Login(c.Context(), req.Username, req.Password)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HTTPOnly: true,
		Secure:   true,
		MaxAge:   900,
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HTTPOnly: true,
		Secure:   true,
		MaxAge:   604800,
	})

	return c.JSON(user)
}

// func (h *Handler) RefreshToken(c *fiber.Ctx) error {
//   var req struct {
//     AccessToken string `json:"access_token"`
//   }
//   if err := c.BodyParser(&req); err != nil {
//     return fiber.ErrBadRequest
//   }
//   refreshToken, error := h.service.
// }
