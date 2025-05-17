package repository

import (
	"context"
	"errors"
	"go-auth/internal/domain/user"
	"time"

	"gorm.io/gorm"
)

type UserResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) user.Repository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	return r.db.WithContext(ctx).Create(u).Error
}

func (r *UserRepository) FindByUserName(ctx context.Context, username string) (*user.User, error) {
	var u user.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&u).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("user not found")
	}

	return &u, err
}

func (r *UserRepository) FindUserById(ctx context.Context, userID uint) (*user.UserResponse, error) {
	var result user.UserResponse
	err := r.db.WithContext(ctx).Model(&user.User{}).Select("id", "username", "email", "created_at").Where("id = ?", userID).Scan(&result).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("user not found")
	}

	return &result, err
}

func (r *UserRepository) CreateRefreshToken(ctx context.Context, token *user.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *UserRepository) FindRefreshToken(ctx context.Context, token string) (*user.RefreshToken, error) {
	var t user.RefreshToken
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&t).Error
	return &t, err
}

func (r *UserRepository) FindRefreshTokenByUserId(ctx context.Context, userID uint) (*user.RefreshToken, error) {
	var t user.RefreshToken

	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&t).Error

	return &t, err
}

func (r *UserRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&user.RefreshToken{}).Error
}

func (r *UserRepository) DeleteRefreshTokensForUser(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&user.RefreshToken{}).Error
}
