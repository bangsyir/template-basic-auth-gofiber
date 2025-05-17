package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo      Repository
	jwtSecret string
}

func NewService(repo Repository, jwtSecret string) *Service {
	return &Service{repo, jwtSecret}
}

func (s *Service) Register(ctx context.Context, username, email, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil
	}
	return s.repo.Create(ctx, &User{
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
	})
}

func (s *Service) Login(ctx context.Context, username, password string) (*User, string, string, error) {
	user, err := s.repo.FindByUserName(ctx, username)
	if err != nil {
		return nil, "", "", errors.New("invalid credentials")
	}
	// compare input password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, "", "", errors.New("invalid credentials")
	}
	accessToken, err := s.generateAccessToken(user.ID)

	if err != nil {
		return nil, "", "", err
	}
	currectRefreshToken, err := s.repo.FindRefreshTokenByUserId(ctx, user.ID)
	isExpired := s.checkIfAccessTokenIsExpired(currectRefreshToken.ExpiresAt)
	if isExpired == false {
		return user, accessToken, currectRefreshToken.Token, nil
	}
	if err := s.repo.DeleteRefreshTokensForUser(ctx, user.ID); err != nil {
		return nil, "", "", err
	}

	refreshToken, _, err := s.generateRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, "", "", err
	}
	return user, accessToken, refreshToken, nil
}

func (s *Service) FindUserByID(ctx context.Context, userID uint) (*UserResponse, error) {
	user, err := s.repo.FindUserById(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) checkIfAccessTokenIsExpired(expiresAt time.Time) bool {
	// make current time minus 15 minues
	threshhold := time.Now()
	return expiresAt.Before(threshhold) || expiresAt.Equal(threshhold)
}

func (s *Service) generateAccessToken(userID uint) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *Service) generateRefreshToken(ctx context.Context, userID uint) (string, time.Time, error) {
	token := generateSecureToken(32)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		Token:     token,
		UserId:    userID,
		ExpiresAt: expiresAt,
	})
	return token, expiresAt, err

}

func generateSecureToken(length int) string {
	key := make([]byte, length)
	rand.Read(key)

	token := base64.URLEncoding.EncodeToString(key)
	return token
}

func (s *Service) RefreshToken(ctx context.Context, c *fiber.Ctx) (uint, error) {
	// 1. get refresh token from cookie
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return 0, fiber.ErrUnauthorized
	}
	// 2. find token in database
	storedToken, err := s.repo.FindRefreshToken(ctx, refreshToken)
	if err != nil || storedToken.ExpiresAt.Before(time.Now()) {
		return 0, fiber.ErrUnauthorized
	}
	// 3. Delete old refresh token
	if err := s.repo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return 0, err
	}

	// 4. generate new tokens
	newAccessToken, err := s.generateAccessToken(storedToken.UserId)
	if err != nil {
		return 0, err
	}
	newRefreshToken, expiresAt, err := s.generateRefreshToken(ctx, storedToken.UserId)
	if err != nil {
		return 0, err
	}

	// 5. set new cookie
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    newAccessToken,
		HTTPOnly: true,
		Secure:   true,
		MaxAge:   900, // 15 minutes
	})
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		HTTPOnly: true,
		Secure:   true,
		Expires:  expiresAt,
	})

	return storedToken.UserId, nil
}
