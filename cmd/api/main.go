package main

import (
	"go-auth/internal/domain/user"
	"go-auth/internal/infrastruture/db"
	repository "go-auth/internal/repository/user"
	http "go-auth/internal/transport/http/user"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	gormDB, err := db.NewSQLiteDB("auth.sqlite")
	if err != nil {
		log.Fatal(err)
	}

	//auto migrate
	gormDB.AutoMigrate(&user.User{}, &user.RefreshToken{})

	//setup dependencies
	userRepo := repository.NewUserRepository(gormDB)
	userService := user.NewService(userRepo, "this-is-secret-you-can't-see-don't-try-to-find")
	userHandler := http.NewUserHandler(userService)

	// create fiber app
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Use(logger.New())
	//routes
	api := app.Group("/api/v1")
	api.Post("/register", userHandler.Register)
	api.Post("/login", userHandler.Login)

	//Start server
	log.Fatal(app.Listen(":3000"))
}
