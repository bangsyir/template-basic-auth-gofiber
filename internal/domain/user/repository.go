package user

import "context"

type Repository interface {
	Create(ctx context.Context, user *User) error
	FindByUserName(ctx context.Context, username string) (*User, error)
	FindUserById(ctx context.Context, userID uint) (*UserResponse, error)
	// refresh token operation
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	FindRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	FindRefreshTokenByUserId(ctx context.Context, userID uint) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteRefreshTokensForUser(ctx context.Context, userID uint) error
}
