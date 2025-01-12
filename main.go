// main.go
package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User struct represents the user model for the database
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `json:"name"`
	Email    string `json:"email" gorm:"unique"`
	Password string `json:"password"`
}

var db *gorm.DB

func init() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize the database
	initDatabase()
}

// initDatabase initializes the database connection and migrates the schema
func initDatabase() {
	var err error
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		dsn = "users.db" // Default to SQLite file if no DSN is provided
	}
	db, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Migrate the schema
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatalf("Failed to migrate database schema: %v", err)
	}
}

func main() {
	app := fiber.New()

	// Middleware
	app.Use(logger.New())

	// Routes
	app.Post("/register", registerUser)
	app.Post("/login", loginUser)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}

// registerUser handles user registration
func registerUser(c *fiber.Ctx) error {
	// Parse request body
	user := new(User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse request body",
		})
	}

	// Validate input
	if user.Name == "" || user.Email == "" || user.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Name, email, and password are required",
		})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password",
		})
	}
	user.Password = string(hashedPassword)

	// Save user to database
	if err := db.Create(user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to save user to database",
		})
	}

	return c.JSON(fiber.Map{
		"message": "User registered successfully",
	})
}

// loginUser handles user login
func loginUser(c *fiber.Ctx) error {
	// Parse request body
	input := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse request body",
		})
	}

	// Validate input
	if input.Email == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Find user by email
	user := new(User)
	if err := db.Where("email = ?", input.Email).First(user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	// Compare passwords
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid email or password",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Login successful",
		// In a real-world application, you would return a JWT or session token here
	})
}
