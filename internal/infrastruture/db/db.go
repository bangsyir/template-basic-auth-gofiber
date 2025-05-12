package db

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewSQLiteDB(dsn string) (*gorm.DB, error) {
	return gorm.Open(sqlite.Open(dsn), nil)
}
