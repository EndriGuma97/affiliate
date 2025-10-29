package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"golang.org/x/crypto/bcrypt"
)

// --- CONFIGURATION ---
const (
	// SMTP settings
	smtpHost     = "mail.needgreatersglobal.com"
	smtpPort     = "587"
	smtpEmail    = "endrig@needgreatersglobal.com"
	smtpPassword = "Assembly3637997Ab,"
	// Session key
	sessionKey = "a-very-secret-key-32-bytes-long"
	// Base URL
	baseURL = "http://localhost:8080"
	// Gemini AI Config
	geminiAPIKey = "AIzaSyD6NfOys90qNnnV597M_u_ePTnR1k-8r1w"
	geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent"
)

// --- GLOBALS ---
var (
	db    *sql.DB               // Database connection pool
	store *sessions.CookieStore // Session store
	tpl   *template.Template    // HTML templates
)

// --- AI SYSTEM PROMPT ---
const aiSystemPrompt = `
You are a classification bot for a Kosovo tourism and consulting website.
Your job is to understand what the user wants and classify their intent.

Respond with ONLY ONE WORD from this list:
- "counseling" - if they want appointments, booking, consulting, therapy, or mention Abel Tattersall
- "places" - if they want to find, see, visit, explore ANY location, attraction, or place in Kosovo
- "other" - for general greetings or unrelated questions

Examples:
User: "I want to see castles" -> places
User: "Show me historical sites" -> places
User: "Where can I find good restaurants?" -> places
User: "I need therapy" -> counseling
User: "Book a consultation" -> counseling
User: "Hello" -> other
User: "What museums are there?" -> places
User: "I want to visit Prizren" -> places
`

// --- MODELS ---

// User defines the user model
type User struct {
	ID                int
	Username          string
	Email             string
	PasswordHash      string
	IsVerified        bool
	IsAdmin           bool
	VerificationToken sql.NullString
	TokenExpiry       sql.NullTime
}

// Place defines the user-submitted location model
type Place struct {
	ID                  int            `json:"ID"`
	Title               string         `json:"Title"`
	Description         string         `json:"Description"`
	Category            string         `json:"Category"`
	Latitude            float64        `json:"Latitude"`
	Longitude           float64        `json:"Longitude"`
	GoogleMapsLink      string         `json:"GoogleMapsLink"`
	SubmittedByUserID   int            `json:"SubmittedByUserID"`
	IsApproved          bool           `json:"IsApproved"`
	CreatedAt           time.Time      `json:"CreatedAt"`
	SubmittedByUsername string         `json:"SubmittedByUsername"`
	CommentCount        int            `json:"CommentCount"`
}

// Comment defines the comment model
type Comment struct {
	ID        int
	PlaceID   int
	UserID    int
	Username  string
	Content   string
	ImageURL  string
	CreatedAt time.Time
}

// --- PAGE DATA MODELS ---

type AdminPageData struct {
	CurrentUser  User
	Users        []User
	Message      string
	Error        string
	PendingCount int
}

type AdminPlacesPageData struct {
	CurrentUser   User
	PendingPlaces []Place
	Message       string
	Error         string
}

type DashboardPageData struct {
	CurrentUser User
}

type MessagePageData struct {
	Title   string
	Message string
}

type PlacesListPageData struct {
	Places       []Place
	SearchQuery  string
	Category     string
	TotalMatches int
}

type PlaceDetailPageData struct {
	Place       Place
	Comments    []Comment
	CurrentUser User
}

type ChatPageData struct {
	Greeting string
}

type PageBundle struct {
	PageName    string
	Data        interface{}
	CurrentUser User
}

// --- API MODELS ---

type AIChatRequest struct {
	Prompt string `json:"prompt"`
}

type AIChatResponse struct {
	Type    string      `json:"type"`
	Content interface{} `json:"content,omitempty"`
}

type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}
type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}
type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// --- MAIN FUNCTION ---
func main() {
	var err error

	// 1. Initialize Database
	db, err = initDB("./users.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	log.Println("Database initialized and tables created.")

	// 2. Initialize Session Store
	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
	}

	// 3. Parse Templates
	tpl = template.Must(template.New("main").Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"formatTime": func(t time.Time) string {
			return t.Format("Jan 2, 2006 at 3:04 PM")
		},
	}).Parse(allTemplates))

	// 4. Setup Routes
	mux := http.NewServeMux()
	setupRoutes(mux)

	// 5. Start Server
	log.Println("Starting server on " + baseURL + " ...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// --- ROUTE SETUP ---
func setupRoutes(mux *http.ServeMux) {
	// --- Static/Public Routes ---
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/verify", verifyHandler)
	mux.HandleFunc("/forgot-password", forgotPasswordHandler)
	mux.HandleFunc("/reset-password", resetPasswordHandler)

	// --- Places & Map Routes ---
	mux.HandleFunc("/map", mapHandler)
	mux.HandleFunc("/places", placesHandler)
	mux.HandleFunc("/place/", placeDetailHandler)
	mux.HandleFunc("/chat", chatPageHandler)
	mux.HandleFunc("/counseling", counselingHandler)

	// --- API Routes ---
	mux.HandleFunc("/api/chat", chatAPIHandler)
	mux.HandleFunc("/api/places", placesAPIHandler)
	mux.HandleFunc("/api/places/submit", submitPlaceHandler)
	mux.HandleFunc("/api/comment", requireAuth(commentHandler))
	mux.HandleFunc("/api/counseling/submit", counselingSubmitHandler)

	// --- Protected Routes ---
	mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
	mux.HandleFunc("/change-password", requireAuth(changePasswordHandler))
	mux.HandleFunc("/delete-account", requireAuth(deleteAccountHandler))

	// --- Admin Routes ---
	mux.HandleFunc("/admin/", requireAdmin(adminHandler))
	mux.HandleFunc("/admin/places", requireAdmin(adminPlacesHandler))
}

// --- DATABASE INITIALIZATION ---
func initDB(filepath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err = db.Ping(); err != nil {
		return nil, err
	}

	// Create tables
	createUserTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_verified BOOLEAN DEFAULT FALSE,
		is_admin BOOLEAN DEFAULT FALSE,
		verification_token TEXT,
		token_expiry DATETIME,
		password_reset_token TEXT,
		reset_token_expiry DATETIME
	);`

	createPlacesTable := `
	CREATE TABLE IF NOT EXISTS places (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT,
		category TEXT NOT NULL,
		latitude REAL DEFAULT 0,
		longitude REAL DEFAULT 0,
		google_maps_link TEXT NOT NULL,
		submitted_by_user_id INTEGER NOT NULL,
		is_approved BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(submitted_by_user_id) REFERENCES users(id)
	);`

	createCommentsTable := `
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		place_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		image_url TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(place_id) REFERENCES places(id) ON DELETE CASCADE,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`

	if _, err = db.Exec(createUserTable); err != nil {
		return nil, err
	}
	if _, err = db.Exec(createPlacesTable); err != nil {
		return nil, err
	}
	if _, err = db.Exec(createCommentsTable); err != nil {
		return nil, err
	}

	// Add columns to existing tables if they don't exist
	db.Exec("ALTER TABLE users ADD COLUMN password_reset_token TEXT")
	db.Exec("ALTER TABLE users ADD COLUMN reset_token_expiry DATETIME")
	db.Exec("ALTER TABLE comments ADD COLUMN image_url TEXT")

	// Add sample admin user if not exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if count == 0 {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		db.Exec("INSERT INTO users (username, email, password_hash, is_verified, is_admin) VALUES (?, ?, ?, ?, ?)",
			"admin", "admin@example.com", string(hashedPassword), true, true)
		log.Println("Created default admin user: admin/admin123")
	}

	return db, nil
}

// --- AUTHENTICATION HELPERS ---
func getCurrentUser(r *http.Request) (User, error) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		return User{}, fmt.Errorf("no valid session")
	}

	var user User
	err := db.QueryRow(
		"SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)

	return user, err
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := getCurrentUser(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !user.IsVerified {
			renderTemplate(w, "message", PageBundle{
				Data: MessagePageData{
					Title:   "Email Not Verified",
					Message: "Please verify your email address to access this page.",
				},
			})
			return
		}
		// Store user in context for the handler
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := getCurrentUser(r)
		if err != nil || !user.IsAdmin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}

// --- PUBLIC HANDLERS ---
func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "home", PageBundle{
		PageName:    "home",
		CurrentUser: user,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		user, _ := getCurrentUser(r)
		renderTemplate(w, "register", PageBundle{
			CurrentUser: user,
		})
		return
	}

	// Handle POST
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderTemplate(w, "register", PageBundle{
			Data: MessagePageData{
				Title:   "Registration Error",
				Message: "Failed to process password.",
			},
		})
		return
	}

	// Generate verification token
	token := generateToken()
	expiry := time.Now().Add(24 * time.Hour)

	// Insert user
	_, err = db.Exec(
		"INSERT INTO users (username, email, password_hash, verification_token, token_expiry) VALUES (?, ?, ?, ?, ?)",
		username, email, string(hashedPassword), token, expiry,
	)
	if err != nil {
		renderTemplate(w, "register", PageBundle{
			Data: MessagePageData{
				Title:   "Registration Error",
				Message: "Username or email already exists.",
			},
		})
		return
	}

	// Send verification email
	verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
	emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify your email: %s\n\nThis link expires in 24 hours.", username, verificationLink)
	
	if err := sendEmail(email, "Verify Your Email", emailBody); err != nil {
		log.Printf("Failed to send verification email: %v", err)
	}

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Registration Successful",
			Message: "Please check your email to verify your account.",
		},
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		user, _ := getCurrentUser(r)
		renderTemplate(w, "login", PageBundle{
			CurrentUser: user,
		})
		return
	}

	// Handle POST
	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	err := db.QueryRow(
		"SELECT id, username, email, password_hash, is_verified, is_admin FROM users WHERE username = ? OR email = ?",
		username, username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsAdmin)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		renderTemplate(w, "login", PageBundle{
			Data: MessagePageData{
				Title:   "Login Failed",
				Message: "Invalid username or password.",
			},
		})
		return
	}

	// Create session
	session, _ := store.Get(r, "session")
	session.Values["user_id"] = user.ID
	session.Save(r, w)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid Token",
				Message: "Verification token is missing.",
			},
		})
		return
	}

	result, err := db.Exec(
		"UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = ? AND token_expiry > ?",
		token, time.Now(),
	)
	if err != nil {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Verification Failed",
				Message: "An error occurred during verification.",
			},
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid or Expired Token",
				Message: "The verification link is invalid or has expired.",
			},
		})
		return
	}

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Email Verified",
			Message: "Your email has been successfully verified. You can now log in.",
		},
	})
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		user, _ := getCurrentUser(r)
		renderTemplate(w, "forgot_password", PageBundle{
			CurrentUser: user,
		})
		return
	}

	// Handle POST
	email := r.FormValue("email")

	var userID int
	var username string
	err := db.QueryRow("SELECT id, username FROM users WHERE email = ?", email).Scan(&userID, &username)

	if err != nil {
		// Don't reveal if email exists or not for security
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Password Reset Email Sent",
				Message: "If an account exists with this email, a password reset link has been sent.",
			},
		})
		return
	}

	// Generate reset token
	token := generateToken()
	expiry := time.Now().Add(1 * time.Hour) // 1 hour expiry

	// Update user with reset token
	_, err = db.Exec(
		"UPDATE users SET password_reset_token = ?, reset_token_expiry = ? WHERE id = ?",
		token, expiry, userID,
	)
	if err != nil {
		log.Printf("Error setting reset token: %v", err)
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Error",
				Message: "An error occurred. Please try again later.",
			},
		})
		return
	}

	// Send password reset email
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)
	emailBody := fmt.Sprintf("Hello %s,\n\nYou requested a password reset. Click the link below to reset your password:\n\n%s\n\nThis link expires in 1 hour.\n\nIf you didn't request this, please ignore this email.", username, resetLink)

	if err := sendEmail(email, "Password Reset Request", emailBody); err != nil {
		log.Printf("Failed to send reset email: %v", err)
	}

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Password Reset Email Sent",
			Message: "If an account exists with this email, a password reset link has been sent.",
		},
	})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if r.Method == http.MethodGet {
		// Verify token exists and is valid
		var count int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM users WHERE password_reset_token = ? AND reset_token_expiry > ?",
			token, time.Now(),
		).Scan(&count)

		if err != nil || count == 0 {
			renderTemplate(w, "message", PageBundle{
				Data: MessagePageData{
					Title:   "Invalid Reset Link",
					Message: "This password reset link is invalid or has expired.",
				},
			})
			return
		}

		user, _ := getCurrentUser(r)
		renderTemplate(w, "reset_password", PageBundle{
			CurrentUser: user,
			Data: map[string]string{
				"token": token,
			},
		})
		return
	}

	// Handle POST
	newPassword := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword != confirmPassword {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Password Mismatch",
				Message: "Passwords do not match.",
			},
		})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Error",
				Message: "Failed to process password.",
			},
		})
		return
	}

	// Update password and clear reset token
	result, err := db.Exec(
		"UPDATE users SET password_hash = ?, password_reset_token = NULL, reset_token_expiry = NULL WHERE password_reset_token = ? AND reset_token_expiry > ?",
		string(hashedPassword), token, time.Now(),
	)

	if err != nil {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Error",
				Message: "An error occurred. Please try again.",
			},
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid Reset Link",
				Message: "This password reset link is invalid or has expired.",
			},
		})
		return
	}

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Password Reset Successful",
			Message: "Your password has been reset successfully. You can now log in with your new password.",
		},
	})
}

// --- PROTECTED HANDLERS ---
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	renderTemplate(w, "dashboard", PageBundle{
		PageName: "dashboard",
		Data: DashboardPageData{
			CurrentUser: user,
		},
		CurrentUser: user,
	})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	if r.Method == http.MethodGet {
		renderTemplate(w, "change_password", PageBundle{
			PageName:    "change_password",
			CurrentUser: user,
		})
		return
	}

	// Handle POST
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Verify current password
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&storedHash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)) != nil {
		renderTemplate(w, "change_password", PageBundle{
			PageName:    "change_password",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Current password is incorrect.",
			},
		})
		return
	}

	// Verify new passwords match
	if newPassword != confirmPassword {
		renderTemplate(w, "change_password", PageBundle{
			PageName:    "change_password",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "New passwords do not match.",
			},
		})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		renderTemplate(w, "change_password", PageBundle{
			PageName:    "change_password",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Failed to process password.",
			},
		})
		return
	}

	// Update password
	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), user.ID)
	if err != nil {
		renderTemplate(w, "change_password", PageBundle{
			PageName:    "change_password",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Failed to update password.",
			},
		})
		return
	}

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Password Changed",
			Message: "Your password has been changed successfully.",
		},
	})
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	if r.Method == http.MethodGet {
		renderTemplate(w, "delete_account", PageBundle{
			PageName:    "delete_account",
			CurrentUser: user,
		})
		return
	}

	// Handle POST
	password := r.FormValue("password")
	confirmation := r.FormValue("confirmation")

	// Verify password
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&storedHash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) != nil {
		renderTemplate(w, "delete_account", PageBundle{
			PageName:    "delete_account",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Password is incorrect.",
			},
		})
		return
	}

	// Verify confirmation text
	if confirmation != "DELETE" {
		renderTemplate(w, "delete_account", PageBundle{
			PageName:    "delete_account",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Please type DELETE to confirm account deletion.",
			},
		})
		return
	}

	// Delete user's comments
	db.Exec("DELETE FROM comments WHERE user_id = ?", user.ID)

	// Delete user's places
	db.Exec("DELETE FROM places WHERE submitted_by_user_id = ?", user.ID)

	// Delete user account
	_, err = db.Exec("DELETE FROM users WHERE id = ?", user.ID)
	if err != nil {
		renderTemplate(w, "delete_account", PageBundle{
			PageName:    "delete_account",
			CurrentUser: user,
			Data: MessagePageData{
				Title:   "Error",
				Message: "Failed to delete account.",
			},
		})
		return
	}

	// Clear session
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")
	session.Save(r, w)

	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Account Deleted",
			Message: "Your account has been permanently deleted.",
		},
	})
}

// --- ADMIN HANDLERS ---
func adminHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		userID, _ := strconv.Atoi(r.FormValue("user_id"))

		var message, errorMsg string

		switch action {
		case "toggle_admin":
			_, err := db.Exec("UPDATE users SET is_admin = NOT is_admin WHERE id = ?", userID)
			if err != nil {
				errorMsg = "Failed to toggle admin status"
			} else {
				message = "Admin status toggled successfully"
			}
		case "delete":
			_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
			if err != nil {
				errorMsg = "Failed to delete user"
			} else {
				message = "User deleted successfully"
			}
		}

		// Redirect to avoid form resubmission
		session, _ := store.Get(r, "session")
		if message != "" {
			session.Values["admin_message"] = message
		}
		if errorMsg != "" {
			session.Values["admin_error"] = errorMsg
		}
		session.Save(r, w)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	// Get message from session if any
	session, _ := store.Get(r, "session")
	message, _ := session.Values["admin_message"].(string)
	errorMsg, _ := session.Values["admin_error"].(string)
	delete(session.Values, "admin_message")
	delete(session.Values, "admin_error")
	session.Save(r, w)

	// Get all users
	rows, err := db.Query("SELECT id, username, email, is_verified, is_admin FROM users ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
		users = append(users, u)
	}

	// Count pending places
	var pendingCount int
	db.QueryRow("SELECT COUNT(*) FROM places WHERE is_approved = FALSE").Scan(&pendingCount)

	renderTemplate(w, "admin", PageBundle{
		PageName: "admin",
		Data: AdminPageData{
			CurrentUser:  user,
			Users:        users,
			Message:      message,
			Error:        errorMsg,
			PendingCount: pendingCount,
		},
		CurrentUser: user,
	})
}

func adminPlacesHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	if r.Method == http.MethodPost {
		placeID, _ := strconv.Atoi(r.FormValue("place_id"))
		action := r.FormValue("action")

		var message, errorMsg string

		switch action {
		case "approve":
			// Get the coordinates from the form
			lat, _ := strconv.ParseFloat(r.FormValue("latitude"), 64)
			lng, _ := strconv.ParseFloat(r.FormValue("longitude"), 64)
			
			_, err := db.Exec("UPDATE places SET is_approved = TRUE, latitude = ?, longitude = ? WHERE id = ?", 
				lat, lng, placeID)
			if err != nil {
				errorMsg = "Failed to approve place"
			} else {
				message = "Place approved successfully with coordinates"
			}
		case "delete":
			// Delete associated comments first (to maintain referential integrity)
			_, err := db.Exec("DELETE FROM comments WHERE place_id = ?", placeID)
			if err != nil {
				log.Printf("Error deleting comments: %v", err)
			}
			
			// Then delete the place
			_, err = db.Exec("DELETE FROM places WHERE id = ?", placeID)
			if err != nil {
				errorMsg = "Failed to delete place"
			} else {
				message = "Place deleted successfully"
			}
		}

		// Redirect to avoid form resubmission
		session, _ := store.Get(r, "session")
		if message != "" {
			session.Values["admin_places_message"] = message
		}
		if errorMsg != "" {
			session.Values["admin_places_error"] = errorMsg
		}
		session.Save(r, w)
		http.Redirect(w, r, "/admin/places", http.StatusSeeOther)
		return
	}

	// Get message from session if any
	session, _ := store.Get(r, "session")
	message, _ := session.Values["admin_places_message"].(string)
	errorMsg, _ := session.Values["admin_places_error"].(string)
	delete(session.Values, "admin_places_message")
	delete(session.Values, "admin_places_error")
	session.Save(r, w)

	// Get ALL places (both pending and approved)
	rows, err := db.Query(`
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude, 
		       p.google_maps_link, p.created_at, p.is_approved, u.username,
		       (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		ORDER BY p.is_approved ASC, p.created_at DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var pendingPlaces []Place
	var approvedPlaces []Place
	
	for rows.Next() {
		var p Place
		var isApproved bool
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude, 
			&p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &isApproved, 
			&p.SubmittedByUsername, &p.CommentCount)
		
		p.IsApproved = isApproved
		
		if isApproved {
			approvedPlaces = append(approvedPlaces, p)
		} else {
			pendingPlaces = append(pendingPlaces, p)
		}
	}

	// Pass both pending and approved places to the template
	type ExtendedAdminPlacesPageData struct {
		CurrentUser     User
		PendingPlaces   []Place
		ApprovedPlaces  []Place
		Message         string
		Error           string
	}

	renderTemplate(w, "admin_places", PageBundle{
		PageName: "admin_places",
		Data: ExtendedAdminPlacesPageData{
			CurrentUser:     user,
			PendingPlaces:   pendingPlaces,
			ApprovedPlaces:  approvedPlaces,
			Message:         message,
			Error:           errorMsg,
		},
		CurrentUser: user,
	})
}

// --- PLACES & MAP HANDLERS ---
func mapHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "map", PageBundle{
		PageName:    "map",
		CurrentUser: user,
	})
}

func placesHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	
	searchQuery := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")

	var places []Place
	var rows *sql.Rows
	var err error

	// Build query based on search parameters with comment counts
	query := `
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude, 
		       p.google_maps_link, p.created_at, u.username,
		       (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		WHERE p.is_approved = TRUE`

	var args []interface{}

	if searchQuery != "" {
		query += " AND (LOWER(p.title) LIKE ? OR LOWER(p.description) LIKE ?)"
		searchParam := "%" + strings.ToLower(searchQuery) + "%"
		args = append(args, searchParam, searchParam)
	}

	if category != "" {
		query += " AND p.category = ?"
		args = append(args, category)
	}

	query += " ORDER BY p.created_at DESC"

	rows, err = db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying places: %v", err)
		renderTemplate(w, "places", PageBundle{
			PageName: "places",
			Data: PlacesListPageData{
				Places:       []Place{},
				SearchQuery:  searchQuery,
				Category:     category,
				TotalMatches: 0,
			},
			CurrentUser: user,
		})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p Place
		err := rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
			&p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername, &p.CommentCount)
		if err != nil {
			log.Printf("Error scanning place: %v", err)
			continue
		}
		places = append(places, p)
	}

	renderTemplate(w, "places", PageBundle{
		PageName: "places",
		Data: PlacesListPageData{
			Places:       places,
			SearchQuery:  searchQuery,
			Category:     category,
			TotalMatches: len(places),
		},
		CurrentUser: user,
	})
}

func placeDetailHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	
	// Extract place ID from URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.NotFound(w, r)
		return
	}
	
	placeID, err := strconv.Atoi(pathParts[2])
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get place details
	var place Place
	err = db.QueryRow(`
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
		       p.google_maps_link, p.created_at, u.username
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		WHERE p.id = ? AND p.is_approved = TRUE
	`, placeID).Scan(&place.ID, &place.Title, &place.Description, &place.Category,
		&place.Latitude, &place.Longitude, &place.GoogleMapsLink, &place.CreatedAt,
		&place.SubmittedByUsername)
	
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get comments
	rows, err := db.Query(`
		SELECT c.id, c.content, c.image_url, c.created_at, u.username
		FROM comments c
		JOIN users u ON c.user_id = u.id
		WHERE c.place_id = ?
		ORDER BY c.created_at DESC
	`, placeID)
	if err != nil {
		log.Printf("Error getting comments: %v", err)
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var c Comment
		var imageURL sql.NullString
		rows.Scan(&c.ID, &c.Content, &imageURL, &c.CreatedAt, &c.Username)
		if imageURL.Valid {
			c.ImageURL = imageURL.String
		}
		comments = append(comments, c)
	}

	renderTemplate(w, "place_detail", PageBundle{
		PageName: "place_detail",
		Data: PlaceDetailPageData{
			Place:       place,
			Comments:    comments,
			CurrentUser: user,
		},
		CurrentUser: user,
	})
}

func submitPlaceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Parse form data (no coordinates from user anymore)
	title := r.FormValue("title")
	description := r.FormValue("description")
	category := r.FormValue("category")
	googleMapsLink := r.FormValue("google_maps_link")

	// Validate required fields
	if title == "" || category == "" || googleMapsLink == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Insert place into database (coordinates default to 0)
	_, err = db.Exec(`
		INSERT INTO places (title, description, category, latitude, longitude, google_maps_link, 
		                   submitted_by_user_id, is_approved)
		VALUES (?, ?, ?, 0, 0, ?, ?, FALSE)`,
		title, description, category, googleMapsLink, user.ID)

	if err != nil {
		log.Printf("Error inserting place: %v", err)
		http.Error(w, "Failed to submit place", http.StatusInternalServerError)
		return
	}

	// Return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Place submitted for review",
	})
}

func commentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := r.Context().Value("user").(User)
	placeID, _ := strconv.Atoi(r.FormValue("place_id"))
	content := r.FormValue("content")
	imageURL := r.FormValue("image_url")

	if content == "" {
		http.Error(w, "Comment cannot be empty", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(`
		INSERT INTO comments (place_id, user_id, content, image_url)
		VALUES (?, ?, ?, ?)
	`, placeID, user.ID, content, imageURL)

	if err != nil {
		log.Printf("Error adding comment: %v", err)
		http.Error(w, "Failed to add comment", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/place/%d", placeID), http.StatusSeeOther)
}

// --- CHAT HANDLERS ---
func chatPageHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "chat", PageBundle{
		PageName: "chat",
		Data: ChatPageData{
			Greeting: "Hello! I'm here to help you. You can ask me about booking appointments with Abel Tattersall or finding places to visit in Kosovo.",
		},
		CurrentUser: user,
	})
}

func counselingHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "counseling", PageBundle{
		PageName:    "counseling",
		CurrentUser: user,
	})
}

func counselingSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	name := r.FormValue("name")
	email := r.FormValue("email")
	date := r.FormValue("date")
	message := r.FormValue("message")

	// Validate required fields
	if name == "" || email == "" || date == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"message": "Name, email, and date are required.",
		})
		return
	}

	// Prepare email body
	emailBody := fmt.Sprintf(`New Consultation Request

Name: %s
Email: %s
Preferred Date: %s
Message: %s

This request was submitted through the Kosovo Explorer website.
`, name, email, date, message)

	// Send email to both recipients
	recipients := []string{
		"atattersall@needgreatersglobal.com",
		"andrewgouma@gmail.com",
	}

	var sendErrors []string
	for _, recipient := range recipients {
		err := sendEmail(recipient, "New Consultation Request from "+name, emailBody)
		if err != nil {
			log.Printf("Failed to send email to %s: %v", recipient, err)
			sendErrors = append(sendErrors, recipient)
		}
	}

	// Send confirmation email to user
	confirmationBody := fmt.Sprintf(`Hello %s,

Thank you for your consultation request with Abel Tattersall.

Your request details:
- Preferred Date: %s
- Message: %s

We will review your request and get back to you soon.

Best regards,
Kosovo Explorer Team
`, name, date, message)

	if err := sendEmail(email, "Consultation Request Received", confirmationBody); err != nil {
		log.Printf("Failed to send confirmation email to %s: %v", email, err)
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	if len(sendErrors) > 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "partial",
			"message": "Request received but some emails failed to send. We will still process your request.",
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"message": "Your consultation request has been submitted successfully. You will receive a confirmation email shortly.",
		})
	}
}

// --- API HANDLERS ---
func chatAPIHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req AIChatRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Call Gemini AI for classification
    intent, err := classifyIntent(req.Prompt)
    if err != nil {
        log.Printf("AI classification error: %v", err)
        // Fallback to keyword-based classification
        intent = fallbackClassification(req.Prompt)
    }

    var response AIChatResponse

    switch intent {
    case "counseling":
        // Return counseling response with form option
        response = AIChatResponse{
            Type:    "counseling",
            Content: map[string]interface{}{
                "message": "I can help you book a consultation with Abel Tattersall. He offers professional consulting services.",
                "showForm": true,
            },
        }

    case "places":
        // Search for places in database
        places := searchPlaces(req.Prompt)
        if len(places) > 0 {
            response = AIChatResponse{
                Type:    "places",
                Content: map[string]interface{}{
                    "message": fmt.Sprintf("I found %d place(s) matching your interest:", len(places)),
                    "places": places,
                },
            }
        } else {
            response = AIChatResponse{
                Type:    "places", 
                Content: map[string]interface{}{
                    "message": "I couldn't find any specific places matching your request. Try being more specific or browse all places.",
                    "places": []Place{},
                },
            }
        }

    default:
        response = AIChatResponse{
            Type:    "other",
            Content: map[string]interface{}{
                "message": "I can help you find interesting places in Kosovo or book a consultation with Abel Tattersall. What would you like to do?",
            },
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
func placesAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get approved places for the map
	rows, err := db.Query(`
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude, 
		       p.google_maps_link, p.created_at, u.username
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		WHERE p.is_approved = TRUE AND p.latitude != 0 AND p.longitude != 0
		ORDER BY p.created_at DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var places []Place
	for rows.Next() {
		var p Place
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
			&p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername)
		places = append(places, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(places)
}

// --- AI HELPER FUNCTIONS ---
func classifyIntent(prompt string) (string, error) {
	// Prepare the request
	geminiReq := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{Text: aiSystemPrompt + "\n\nUser: " + prompt},
				},
			},
		},
	}

	jsonData, err := json.Marshal(geminiReq)
	if err != nil {
		return "", err
	}

	// Make the API call
	url := geminiAPIURL + "?key=" + geminiAPIKey
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Parse response
	var geminiResp GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return "", err
	}

	// Check for API error
	if geminiResp.Error != nil {
		return "", fmt.Errorf("Gemini API error: %s", geminiResp.Error.Message)
	}

	// Extract the classification
	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		classification := strings.TrimSpace(strings.ToLower(geminiResp.Candidates[0].Content.Parts[0].Text))
		
		// Ensure we got a valid classification
		if classification == "counseling" || classification == "places" || classification == "other" {
			return classification, nil
		}
	}

	return "other", nil
}

func fallbackClassification(prompt string) string {
    lowerPrompt := strings.ToLower(prompt)
    
    // Expanded counseling keywords
    counselingKeywords := []string{
        "appointment", "book", "schedule", "abel", "tattersall", 
        "consulting", "consultation", "session", "meeting", "therapy",
        "counseling", "advice", "help me with", "coaching",
    }
    
    // Expanded places keywords
    placesKeywords := []string{
        "place", "visit", "find", "recommend", "where", "location", 
        "hike", "food", "restaurant", "castle", "prizren", "kosovo",
        "museum", "monument", "church", "mosque", "park", "nature",
        "historical", "heritage", "tourist", "attraction", "see",
        "explore", "discover", "go to", "travel", "trip", "tour",
        "shopping", "market", "bazaar", "things to do",
    }
    
    // Check counseling keywords first (higher priority)
    for _, keyword := range counselingKeywords {
        if strings.Contains(lowerPrompt, keyword) {
            return "counseling"
        }
    }
    
    // Then check places keywords
    for _, keyword := range placesKeywords {
        if strings.Contains(lowerPrompt, keyword) {
            return "places"
        }
    }
    
    return "other"
}

func searchPlaces(prompt string) []Place {
    var places []Place
    
    // Convert prompt to lowercase for better matching
    lowerPrompt := strings.ToLower(prompt)
    
    // Extract key search terms from the prompt
    var searchTerms []string
    
    // Common place-related keywords to search for
    placeKeywords := map[string][]string{
        "castle": {"castle", "fortress", "fort", "kala", "kalaja"},
        "museum": {"museum", "gallery", "art", "history"},
        "restaurant": {"restaurant", "food", "dining", "eat", "cuisine"},
        "nature": {"park", "mountain", "lake", "hiking", "trail", "nature"},
        "church": {"church", "cathedral", "monastery", "mosque", "temple"},
        "historical": {"historical", "heritage", "ancient", "old", "monument"},
        "shopping": {"shop", "mall", "market", "bazaar", "store"},
    }
    
    // Check which keywords are in the prompt
    for _, synonyms := range placeKeywords {
        for _, synonym := range synonyms {
            if strings.Contains(lowerPrompt, synonym) {
                searchTerms = append(searchTerms, synonyms...)
                break
            }
        }
    }
    
    // If no specific keywords found, use general search
    if len(searchTerms) == 0 {
        // Extract potential search terms from prompt
        words := strings.Fields(lowerPrompt)
        for _, word := range words {
            // Skip common words
            if len(word) > 3 && word != "want" && word != "show" && word != "find" && word != "where" {
                searchTerms = append(searchTerms, word)
            }
        }
    }
    
    // Build SQL query with OR conditions for all search terms
    if len(searchTerms) > 0 {
        query := `
            SELECT DISTINCT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
                   p.google_maps_link, p.created_at, u.username
            FROM places p
            JOIN users u ON p.submitted_by_user_id = u.id
            WHERE p.is_approved = TRUE AND (`
        
        conditions := []string{}
        args := []interface{}{}
        
        for _, term := range searchTerms {
            conditions = append(conditions, 
                "(LOWER(p.title) LIKE ? OR LOWER(p.description) LIKE ? OR LOWER(p.category) LIKE ?)")
            searchPattern := "%" + term + "%"
            args = append(args, searchPattern, searchPattern, searchPattern)
        }
        
        query += strings.Join(conditions, " OR ") + ") ORDER BY p.created_at DESC LIMIT 10"
        
        rows, err := db.Query(query, args...)
        if err != nil {
            log.Printf("Error searching places: %v", err)
            return places
        }
        defer rows.Close()
        
        for rows.Next() {
            var p Place
            rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
                &p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername)
            places = append(places, p)
        }
    }
    
    return places
}
// --- EMAIL HELPER ---
func sendEmail(to, subject, body string) error {
    auth := smtp.PlainAuth("", smtpEmail, smtpPassword, smtpHost)
    
    // Properly formatted email with all necessary headers
    msg := []byte(
        "MIME-Version: 1.0\r\n" +
        "From: " + smtpEmail + "\r\n" +
        "To: " + to + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
        "\r\n" +
        body,
    )
    
    addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
    return smtp.SendMail(addr, auth, smtpEmail, []string{to}, msg)
}

// --- UTILITY FUNCTIONS ---
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	if err := tpl.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// --- TEMPLATES ---
const allTemplates = `
{{define "layout"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kosovo Explorer</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --secondary-gradient: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --dark-bg: #0a0e27;
            --card-bg: rgba(255, 255, 255, 0.05);
            --text-light: #ffffff;
            --text-gray: #a0a0a0;
            --border-color: rgba(255, 255, 255, 0.1);
            --shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--dark-bg);
            background-image: 
                radial-gradient(circle at 20% 80%, rgba(102, 126, 234, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(118, 75, 162, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 40%, rgba(240, 147, 251, 0.05) 0%, transparent 50%);
            min-height: 100vh;
            color: var(--text-light);
            line-height: 1.6;
        }

        .navbar {
            background: rgba(10, 14, 39, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .navbar-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .navbar-brand {
            font-size: 1.5rem;
            font-weight: 700;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-decoration: none;
        }

        .navbar-links {
            display: flex;
            gap: 2rem;
            align-items: center;
        }

        .navbar-links a {
            color: var(--text-gray);
            text-decoration: none;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .navbar-links a:hover {
            color: var(--text-light);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .hero {
            text-align: center;
            padding: 4rem 2rem;
            margin-bottom: 4rem;
        }

        .hero h1 {
            font-size: 3.5rem;
            font-weight: 800;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1.5rem;
        }

        .hero p {
            font-size: 1.25rem;
            color: var(--text-gray);
            max-width: 600px;
            margin: 0 auto 2rem;
        }

        .btn {
            display: inline-block;
            padding: 1rem 2rem;
            background: var(--primary-gradient);
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 1rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }

        .btn-secondary {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 4rem;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(102, 126, 234, 0.3);
            box-shadow: var(--shadow);
        }

        .card-icon {
            width: 60px;
            height: 60px;
            background: var(--primary-gradient);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .card h3 {
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }

        .card p {
            color: var(--text-gray);
            line-height: 1.8;
        }

        .form-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 3rem;
            max-width: 500px;
            margin: 0 auto;
            backdrop-filter: blur(10px);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-light);
            font-weight: 500;
        }

        /* FIXED DROPDOWN VISIBILITY */
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: white;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-group select option {
            background: #1a1a2e;
            color: white;
        }

        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: rgba(102, 126, 234, 0.5);
            background: rgba(0, 0, 0, 0.7);
        }

        .dashboard-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 3rem;
            backdrop-filter: blur(10px);
            margin-bottom: 2rem;
        }

        .admin-table {
            width: 100%;
            overflow-x: auto;
        }

        .admin-table table {
            width: 100%;
            border-collapse: collapse;
        }

        .admin-table th,
        .admin-table td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .admin-table th {
            background: rgba(255, 255, 255, 0.03);
            font-weight: 600;
            color: var(--text-light);
        }

        .admin-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }

        .action-form {
            display: inline-block;
            margin-right: 0.5rem;
        }

        .btn-admin {
            padding: 0.5rem 1rem;
            background: var(--primary-gradient);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .btn-delete {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            padding: 0.5rem 1rem;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .btn-delete:hover {
            background: linear-gradient(135deg, #c0392b, #a93226);
        }

        .alert-success {
            background: linear-gradient(135deg, #11998e, #38ef7d);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }

        .alert-error {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }

        #map {
            height: 600px;
            width: 100%;
            border-radius: 20px;
            overflow: hidden;
            margin-bottom: 2rem;
        }

        .map-controls {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(10px);
        }

        .places-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .place-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            cursor: pointer;
            position: relative;
        }

        .place-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow);
            border-color: rgba(102, 126, 234, 0.3);
        }

        .place-card h3 {
            margin-bottom: 0.5rem;
            color: var(--text-light);
        }

        .place-card-meta {
            font-size: 0.9rem;
            color: var(--text-gray);
            margin-bottom: 1rem;
        }

        .place-card-desc {
            color: var(--text-gray);
            line-height: 1.6;
            margin-bottom: 1rem;
        }

        .place-card-coords {
            font-size: 0.85rem;
            color: var(--text-gray);
            font-family: monospace;
            background: rgba(0, 0, 0, 0.2);
            padding: 0.5rem;
            border-radius: 5px;
        }

        .comment-section {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            margin-top: 2rem;
        }

        .comment {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
        }

        .comment-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            color: var(--text-gray);
        }

        .comment-content {
            color: var(--text-light);
        }

        .chat-container {
            max-width: 800px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            overflow: hidden;
        }

        .chat-messages {
            height: 500px;
            overflow-y: auto;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .chat-message {
            padding: 1rem 1.5rem;
            border-radius: 15px;
            max-width: 70%;
            word-wrap: break-word;
        }

        .chat-message.user {
            align-self: flex-end;
            background: var(--primary-gradient);
            color: white;
        }

        .chat-message.ai {
            align-self: flex-start;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border-color);
        }

        .chat-input {
            display: flex;
            gap: 1rem;
            padding: 1.5rem;
            background: rgba(0, 0, 0, 0.2);
            border-top: 1px solid var(--border-color);
        }

        .chat-input input {
            flex: 1;
            padding: 1rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: white;
            font-size: 1rem;
        }

        .chat-input input:focus {
            outline: none;
            border-color: rgba(102, 126, 234, 0.5);
        }

        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2rem;
            }
            
            .navbar-links {
                flex-direction: column;
                gap: 1rem;
            }
            
            .places-grid {
                grid-template-columns: 1fr;
            }
            
            .chat-message {
                max-width: 85%;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <a href="/" class="navbar-brand">🏔️ Kosovo Explorer</a>
            <div class="navbar-links">
                {{if .CurrentUser.ID}}
                    <a href="/dashboard">Dashboard</a>
                    <a href="/map">Map</a>
                    <a href="/places">Places</a>
                    <a href="/chat">AI Assistant</a>
                    {{if .CurrentUser.IsAdmin}}
                        <a href="/admin/">Admin</a>
                    {{end}}
                    <span style="color: var(--text-gray);">Hello, {{.CurrentUser.Username}}</span>
                    <a href="/logout" class="btn-secondary" style="padding: 0.5rem 1rem;">Logout</a>
                {{else}}
                    <a href="/map">Map</a>
                    <a href="/places">Places</a>
                    <a href="/chat">AI Assistant</a>
                    <a href="/login">Login</a>
                    <a href="/register" class="btn" style="padding: 0.5rem 1.5rem;">Sign Up</a>
                {{end}}
            </div>
        </div>
    </nav>
{{end}}

{{define "home"}}
{{template "layout" .}}
<div class="hero">
    <h1>Discover Kosovo</h1>
    <p>Explore hidden gems, share your favorite spots, and connect with a community of explorers</p>
    <div style="display: flex; gap: 1rem; justify-content: center;">
        <a href="/map" class="btn">Explore Map</a>
        <a href="/chat" class="btn-secondary btn">AI Assistant</a>
    </div>
</div>

<div class="container">
    <div class="card-grid">
        <div class="card">
            <div class="card-icon">📍</div>
            <h3>Community Map</h3>
            <p>Discover places recommended by locals and travelers. Find hidden restaurants, scenic viewpoints, and cultural landmarks.</p>
        </div>
        <div class="card">
            <div class="card-icon">🤖</div>
            <h3>AI Assistant</h3>
            <p>Get personalized recommendations and book appointments with our AI-powered chat assistant.</p>
        </div>
        <div class="card">
            <div class="card-icon">✨</div>
            <h3>Share & Contribute</h3>
            <p>Add your favorite spots to help others discover the beauty of Kosovo. Every contribution makes our community stronger.</p>
        </div>
    </div>
</div>
{{end}}

{{define "register"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1 style="text-align: center; margin-bottom: 2rem;">Create Account</h1>
        {{if .Data}}
            {{if .Data.Message}}
            <div class="alert-error">{{.Data.Message}}</div>
            {{end}}
        {{end}}
        <form method="POST" action="/register">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required minlength="6">
            </div>
            <button type="submit" class="btn" style="width: 100%;">Sign Up</button>
            <p style="text-align: center; margin-top: 1rem; color: var(--text-gray);">
                Already have an account? <a href="/login" style="color: #667eea;">Log in</a>
            </p>
        </form>
    </div>
</div>
{{end}}

{{define "login"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1 style="text-align: center; margin-bottom: 2rem;">Welcome Back</h1>
        {{if .Data}}
            {{if .Data.Message}}
            <div class="alert-error">{{.Data.Message}}</div>
            {{end}}
        {{end}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <p style="text-align: right; margin-bottom: 1rem;">
                <a href="/forgot-password" style="color: var(--text-gray); font-size: 0.9rem;">Forgot password?</a>
            </p>
            <button type="submit" class="btn" style="width: 100%;">Log In</button>
            <p style="text-align: center; margin-top: 1rem; color: var(--text-gray);">
                Don't have an account? <a href="/register" style="color: #667eea;">Sign up</a>
            </p>
        </form>
    </div>
</div>
{{end}}

{{define "message"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1 style="text-align: center; margin-bottom: 2rem;">{{.Data.Title}}</h1>
        <p style="text-align: center; color: var(--text-gray);">{{.Data.Message}}</p>
        <div style="text-align: center; margin-top: 2rem;">
            <a href="/" class="btn">Go Home</a>
        </div>
    </div>
</div>
{{end}}

{{define "dashboard"}}
{{template "layout" .}}
<div class="container">
    <div class="dashboard-card">
        <h1>Welcome back, {{.Data.CurrentUser.Username}}!</h1>
        <p style="color: var(--text-gray); margin-bottom: 2rem;">
            {{if .Data.CurrentUser.IsAdmin}}
                You have administrator privileges.
            {{else}}
                Regular user account.
            {{end}}
        </p>
        
        <div class="card-grid">
            <div class="card">
                <h3>🗺️ Explore Map</h3>
                <p>View all approved places on an interactive map.</p>
                <a href="/map" class="btn" style="margin-top: 1rem;">Open Map</a>
            </div>
            <div class="card">
                <h3>📍 Browse Places</h3>
                <p>Search and filter through all community-submitted locations.</p>
                <a href="/places" class="btn" style="margin-top: 1rem;">View Places</a>
            </div>
            <div class="card">
                <h3>💬 AI Assistant</h3>
                <p>Get help finding places or booking appointments.</p>
                <a href="/chat" class="btn" style="margin-top: 1rem;">Start Chat</a>
            </div>
            {{if .Data.CurrentUser.IsAdmin}}
            <div class="card">
                <h3>⚙️ Admin Panel</h3>
                <p>Manage users and review pending places.</p>
                <a href="/admin/" class="btn" style="margin-top: 1rem;">Admin Dashboard</a>
            </div>
            {{end}}
        </div>

        <h2 style="margin-top: 3rem; margin-bottom: 1rem;">Account Settings</h2>
        <div class="card-grid">
            <div class="card">
                <h3>🔐 Change Password</h3>
                <p>Update your account password for security.</p>
                <a href="/change-password" class="btn" style="margin-top: 1rem;">Change Password</a>
            </div>
            <div class="card" style="border-color: rgba(244, 67, 54, 0.3);">
                <h3 style="color: #f44336;">🗑️ Delete Account</h3>
                <p>Permanently delete your account and all data.</p>
                <a href="/delete-account" class="btn" style="margin-top: 1rem; background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);">Delete Account</a>
            </div>
        </div>
    </div>
</div>
{{end}}

{{define "admin"}}
{{template "layout" .}}
<div class="container">
    <div class="dashboard-card">
        <h1>Admin Dashboard</h1>
        <p style="color: var(--text-gray); margin-bottom: 2rem;">
            Manage users and content across the platform.
        </p>
        
        {{if .Data.Error}}
            <div class="alert-error">{{.Data.Error}}</div>
        {{end}}
        {{if .Data.Message}}
            <div class="alert-success">{{.Data.Message}}</div>
        {{end}}

        <div style="margin-bottom: 2rem;">
            <a href="/admin/places" class="btn">
                Manage Places ({{.Data.PendingCount}} pending)
            </a>
        </div>

        <h2 style="margin-bottom: 1.5rem;">User Management</h2>
        <div class="admin-table">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Verified</th>
                        <th>Admin</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.Users}}
                    <tr>
                        <td>{{.ID}}</td>
                        <td>{{.Username}}</td>
                        <td>{{.Email}}</td>
                        <td>{{if .IsVerified}}✅{{else}}❌{{end}}</td>
                        <td>{{if .IsAdmin}}✅{{else}}❌{{end}}</td>
                        <td>
                            <form action="/admin/" method="POST" class="action-form">
                                <input type="hidden" name="user_id" value="{{.ID}}">
                                <input type="hidden" name="action" value="toggle_admin">
                                <button type="submit" class="btn-admin">Toggle Admin</button>
                            </form>
                            <form action="/admin/" method="POST" class="action-form" onsubmit="return confirm('Are you sure you want to delete this user?');">
                                <input type="hidden" name="user_id" value="{{.ID}}">
                                <input type="hidden" name="action" value="delete">
                                <button type="submit" class="btn-delete">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</div>
{{end}}

{{define "admin_places"}}
{{template "layout" .}}
<div class="container">
    <div class="dashboard-card">
        <h1>Manage Places</h1>
        <p style="color: var(--text-gray); margin-bottom: 2rem;">
            Approve pending submissions and manage all places.
        </p>
        <a href="/admin/" class="btn-secondary" style="padding: 0.8rem 1.5rem; text-decoration: none; display: inline-block; margin-bottom: 2rem;">← Back to Main Admin</a>
        
        {{if .Data.Error}}
            <div class="alert-error" style="margin-top: 1.5rem;">{{.Data.Error}}</div>
        {{end}}
        {{if .Data.Message}}
            <div class="alert-success" style="margin-top: 1.5rem;">{{.Data.Message}}</div>
        {{end}}
        
        <!-- Pending Places Section -->
        <h2 style="margin-top: 2rem; margin-bottom: 1.5rem; color: var(--text-light);">
            📋 Pending Review ({{len .Data.PendingPlaces}})
        </h2>
        
        {{if .Data.PendingPlaces}}
        <div class="admin-table" style="margin-bottom: 3rem;">
            <table>
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Submitted By</th>
                        <th>Category</th>
                        <th>Google Maps</th>
                        <th>Set Coordinates</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.PendingPlaces}}
                    <tr>
                        <td>
                            <strong>{{.Title}}</strong>
                            <p style="font-size: 0.9rem; color: var(--text-gray);">{{.Description}}</p>
                        </td>
                        <td>{{.SubmittedByUsername}}</td>
                        <td>{{.Category}}</td>
                        <td>
                            <a href="{{.GoogleMapsLink}}" target="_blank" style="color: #667eea;">View</a>
                        </td>
                        <td>
                            <form action="/admin/places" method="POST" class="action-form">
                                <input type="hidden" name="place_id" value="{{.ID}}">
                                <input type="hidden" name="action" value="approve">
                                <input type="number" step="0.000001" name="latitude" placeholder="Latitude" required style="width: 120px; margin-bottom: 0.5rem;">
                                <input type="number" step="0.000001" name="longitude" placeholder="Longitude" required style="width: 120px;">
                        </td>
                        <td>
                                <button type="submit" class="btn-admin" style="background: #2ecc71;">Approve</button>
                            </form>
                            <form action="/admin/places" method="POST" class="action-form" onsubmit="return confirm('Are you sure you want to delete this submission?');">
                                <input type="hidden" name="place_id" value="{{.ID}}">
                                <input type="hidden" name="action" value="delete">
                                <button type="submit" class="btn-delete">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{else}}
        <p style="color: var(--text-gray); margin-bottom: 3rem;">No pending submissions.</p>
        {{end}}

        <!-- Approved Places Section -->
        <h2 style="margin-top: 2rem; margin-bottom: 1.5rem; color: var(--text-light);">
            ✅ Approved Places ({{len .Data.ApprovedPlaces}})
        </h2>
        
        {{if .Data.ApprovedPlaces}}
        <div class="admin-table">
            <table>
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Submitted By</th>
                        <th>Category</th>
                        <th>Coordinates</th>
                        <th>Comments</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.ApprovedPlaces}}
                    <tr>
                        <td>
                            <strong>{{.Title}}</strong>
                            <p style="font-size: 0.9rem; color: var(--text-gray);">{{.Description}}</p>
                        </td>
                        <td>{{.SubmittedByUsername}}</td>
                        <td>{{.Category}}</td>
                        <td>
                            {{if ne .Latitude 0.0}}
                                <span style="font-family: monospace; font-size: 0.85rem;">{{.Latitude}}, {{.Longitude}}</span>
                            {{else}}
                                <span style="color: var(--text-gray);">Not set</span>
                            {{end}}
                        </td>
                        <td>{{.CommentCount}}</td>
                        <td>
                            <div style="display: flex; gap: 0.5rem;">
                                <a href="/place/{{.ID}}" target="_blank" class="btn-admin" style="text-decoration: none; display: inline-block;">View</a>
                                <form action="/admin/places" method="POST" class="action-form" onsubmit="return confirm('⚠️ WARNING: This will permanently delete this place and all {{.CommentCount}} comment(s). Are you sure?');">
                                    <input type="hidden" name="place_id" value="{{.ID}}">
                                    <input type="hidden" name="action" value="delete">
                                    <button type="submit" class="btn-delete">Delete</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{else}}
        <p style="color: var(--text-gray);">No approved places yet.</p>
        {{end}}
    </div>
</div>
{{end}}

{{define "map"}}
{{template "layout" .}}
<div class="container">
    <h1 style="text-align: center; margin-bottom: 2rem;">Explore Kosovo</h1>
    
    <div class="map-controls">
        <div style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
            <select id="category-filter" class="form-control" style="flex: 1; min-width: 200px;">
                <option value="">All Categories</option>
                <option value="Restaurant">Restaurants</option>
                <option value="Nature">Nature</option>
                <option value="Culture">Culture</option>
                <option value="Shopping">Shopping</option>
                <option value="Other">Other</option>
            </select>
            {{if .CurrentUser.ID}}
            <button class="btn" onclick="showAddPlaceModal()">+ Add New Place</button>
            {{end}}
        </div>
    </div>

    <div id="map"></div>
</div>

{{if .CurrentUser.ID}}
<!-- Add Place Modal -->
<div id="add-place-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.8); z-index: 1000; padding: 2rem;">
    <div class="form-card" style="max-width: 600px; margin: 2rem auto; max-height: 90vh; overflow-y: auto;">
        <h2>Add New Place</h2>
        <p style="color: var(--text-gray); margin-bottom: 1.5rem;">Submit a place for admin review. Coordinates will be set by admin.</p>
        
        <form id="add-place-form">
            <div class="form-group">
                <label for="title">Place Name*</label>
                <input type="text" id="title" name="title" required>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" rows="3"></textarea>
            </div>
            <div class="form-group">
                <label for="category">Category*</label>
                <select id="category" name="category" required>
                    <option value="">Select a category</option>
                    <option value="Restaurant">Restaurant</option>
                    <option value="Nature">Nature</option>
                    <option value="Culture">Culture</option>
                    <option value="Shopping">Shopping</option>
                    <option value="Other">Other</option>
                </select>
            </div>
            <div class="form-group">
                <label for="google_maps_link">Google Maps Link*</label>
                <input type="url" id="google_maps_link" name="google_maps_link" placeholder="https://maps.google.com/..." required>
            </div>
            <div style="display: flex; gap: 1rem;">
                <button type="submit" class="btn" style="flex: 1;">Submit for Review</button>
                <button type="button" class="btn-secondary btn" style="flex: 1;" onclick="hideAddPlaceModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>
{{end}}

<script>
    // Initialize map centered on Kosovo
    var map = L.map('map').setView([42.6026, 20.9030], 8);
    
    // Add OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors'
    }).addTo(map);

    var markers = [];

    // Load places from API
    async function loadPlaces(category = '') {
        try {
            const response = await fetch('/api/places');
            const places = await response.json();
            
            // Clear existing markers
            markers.forEach(marker => map.removeLayer(marker));
            markers = [];

            // Add markers for each place
            places.forEach(place => {
                if (category && place.Category !== category) return;

                const marker = L.marker([place.Latitude, place.Longitude])
                    .bindPopup(
                        '<div style="min-width: 200px;">' +
                            '<h3 style="margin: 0 0 0.5rem 0;">' + escapeHtml(place.Title) + '</h3>' +
                            '<p style="margin: 0 0 0.5rem 0; color: #666;">' + escapeHtml(place.Description || 'No description') + '</p>' +
                            '<div style="font-size: 0.9rem; color: #888;">' +
                                '<strong>Category:</strong> ' + escapeHtml(place.Category) + '<br>' +
                                '<strong>Added by:</strong> ' + escapeHtml(place.SubmittedByUsername) +
                                '<br><a href="/place/' + place.ID + '">View Details & Comments</a>' +
                            '</div>' +
                        '</div>'
                    );
                
                marker.addTo(map);
                markers.push(marker);
            });
        } catch (error) {
            console.error('Error loading places:', error);
        }
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    // Category filter
    document.getElementById('category-filter').addEventListener('change', (e) => {
        loadPlaces(e.target.value);
    });

    // Load places on page load
    loadPlaces();

    {{if .CurrentUser.ID}}
    // Add place functionality
    function showAddPlaceModal() {
        document.getElementById('add-place-modal').style.display = 'block';
    }

    function hideAddPlaceModal() {
        document.getElementById('add-place-modal').style.display = 'none';
        document.getElementById('add-place-form').reset();
    }

    // Handle form submission
    document.getElementById('add-place-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);
        
        try {
            const response = await fetch('/api/places/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(data)
            });

            if (response.ok) {
                alert('Place submitted successfully! It will appear on the map after admin approval.');
                hideAddPlaceModal();
            } else {
                alert('Failed to submit place. Please try again.');
            }
        } catch (error) {
            console.error('Error submitting place:', error);
            alert('An error occurred. Please try again.');
        }
    });
    {{end}}
</script>
{{end}}

{{define "places"}}
{{template "layout" .}}
<div class="container">
    <h1 style="text-align: center; margin-bottom: 2rem;">Community Places</h1>
    
    <div class="map-controls">
        <form method="GET" action="/places" style="display: flex; gap: 1rem; flex-wrap: wrap;">
            <input type="text" name="q" placeholder="Search places..." value="{{.Data.SearchQuery}}" 
                   style="flex: 2; min-width: 200px; padding: 0.8rem; background: rgba(0, 0, 0, 0.5); 
                          border: 1px solid var(--border-color); border-radius: 10px; color: white;">
            <select name="category" style="flex: 1; min-width: 150px; padding: 0.8rem; background: rgba(0, 0, 0, 0.5); 
                    border: 1px solid var(--border-color); border-radius: 10px; color: white;">
                <option value="">All Categories</option>
                <option value="Restaurant" {{if eq .Data.Category "Restaurant"}}selected{{end}}>Restaurants</option>
                <option value="Nature" {{if eq .Data.Category "Nature"}}selected{{end}}>Nature</option>
                <option value="Culture" {{if eq .Data.Category "Culture"}}selected{{end}}>Culture</option>
                <option value="Shopping" {{if eq .Data.Category "Shopping"}}selected{{end}}>Shopping</option>
                <option value="Other" {{if eq .Data.Category "Other"}}selected{{end}}>Other</option>
            </select>
            <button type="submit" class="btn">Search</button>
        </form>
    </div>

    <p style="color: var(--text-gray); margin-bottom: 2rem;">
        Found {{.Data.TotalMatches}} place{{if ne .Data.TotalMatches 1}}s{{end}}
        {{if .Data.SearchQuery}}matching "{{.Data.SearchQuery}}"{{end}}
        {{if .Data.Category}}in category "{{.Data.Category}}"{{end}}
    </p>

    <div class="places-grid">
        {{range .Data.Places}}
        <div class="place-card" onclick="window.location.href='/place/{{.ID}}'">
            <h3>{{.Title}}</h3>
            <div class="place-card-meta">
                <span>📍 {{.Category}}</span> | 
                <span>👤 {{.SubmittedByUsername}}</span> |
                <span>💬 {{.CommentCount}} comments</span>
            </div>
            <p class="place-card-desc">{{.Description}}</p>
            {{if ne .Latitude 0.0}}
            <div class="place-card-coords">
                📌 {{.Latitude}}, {{.Longitude}}
            </div>
            {{end}}
            <a href="{{.GoogleMapsLink}}" target="_blank" class="btn-secondary btn" style="margin-top: 1rem; display: inline-block;" onclick="event.stopPropagation();">
                View on Google Maps →
            </a>
        </div>
        {{else}}
        <div style="grid-column: 1/-1; text-align: center; padding: 3rem;">
            <p style="color: var(--text-gray);">No places found. Be the first to add one!</p>
            {{if not $.CurrentUser.ID}}
            <a href="/login" class="btn" style="margin-top: 1rem;">Login to Add Places</a>
            {{else}}
            <a href="/map" class="btn" style="margin-top: 1rem;">Go to Map</a>
            {{end}}
        </div>
        {{end}}
    </div>
</div>
{{end}}

{{define "place_detail"}}
{{template "layout" .}}
<div class="container">
    <div class="dashboard-card">
        <a href="/places" class="btn-secondary" style="padding: 0.8rem 1.5rem; text-decoration: none; display: inline-block; margin-bottom: 2rem;">← Back to Places</a>
        
        <h1>{{.Data.Place.Title}}</h1>
        <div style="font-size: 1rem; color: var(--text-gray); margin-bottom: 1.5rem;">
            <span>📍 {{.Data.Place.Category}}</span> | 
            <span>👤 Added by {{.Data.Place.SubmittedByUsername}}</span> |
            <span>📅 {{.Data.Place.CreatedAt.Format "Jan 2, 2006"}}</span>
        </div>
        
        <p style="font-size: 1.1rem; line-height: 1.8; margin-bottom: 2rem;">{{.Data.Place.Description}}</p>
        
        {{if ne .Data.Place.Latitude 0.0}}
        <div style="background: rgba(0, 0, 0, 0.2); padding: 1rem; border-radius: 10px; margin-bottom: 2rem;">
            <strong>Coordinates:</strong> {{.Data.Place.Latitude}}, {{.Data.Place.Longitude}}
        </div>
        {{end}}
        
        <a href="{{.Data.Place.GoogleMapsLink}}" target="_blank" class="btn">
            View on Google Maps →
        </a>
    </div>

    <div class="comment-section">
        <h2>Comments ({{len .Data.Comments}})</h2>
        
        {{if .CurrentUser.ID}}
        <form action="/api/comment" method="POST" style="margin-bottom: 2rem;">
            <input type="hidden" name="place_id" value="{{.Data.Place.ID}}">
            <div class="form-group">
                <label for="content">Add a comment</label>
                <textarea id="content" name="content" rows="3" required placeholder="Share your experience..."></textarea>
            </div>
            <div class="form-group">
                <label for="image_url">Image URL (optional)</label>
                <input type="url" id="image_url" name="image_url" placeholder="https://example.com/image.jpg">
                <small style="color: var(--text-gray); font-size: 0.85rem;">Add a single image to your comment by providing a URL</small>
            </div>
            <button type="submit" class="btn">Post Comment</button>
        </form>
        {{else}}
        <p style="color: var(--text-gray); margin-bottom: 2rem;">
            <a href="/login" style="color: #667eea;">Login</a> to leave a comment
        </p>
        {{end}}

        {{range .Data.Comments}}
        <div class="comment">
            <div class="comment-header">
                <strong>{{.Username}}</strong>
                <span>{{.CreatedAt.Format "Jan 2, 2006 at 3:04 PM"}}</span>
            </div>
            <div class="comment-content">
                {{.Content}}
            </div>
            {{if .ImageURL}}
            <div style="margin-top: 1rem;">
                <img src="{{.ImageURL}}" alt="Comment image" style="max-width: 100%; max-height: 400px; border-radius: 10px; object-fit: contain;">
            </div>
            {{end}}
        </div>
        {{else}}
        <p style="color: var(--text-gray);">No comments yet. Be the first to share your thoughts!</p>
        {{end}}
    </div>
</div>
{{end}}

{{define "chat"}}
{{template "layout" .}}
<div class="container">
    <div class="chat-container">
        <div class="chat-messages" id="chat-messages">
            <div class="chat-message ai">
                {{.Data.Greeting}}
            </div>
        </div>
        <form class="chat-input" id="chat-form">
            <input type="text" id="prompt-input" placeholder="Ask me anything..." required autocomplete="off">
            <button type="submit" class="btn" id="chat-submit-btn">Send</button>
        </form>
    </div>
</div>

<script>
    const chatForm = document.getElementById('chat-form');
    const promptInput = document.getElementById('prompt-input');
    const chatMessages = document.getElementById('chat-messages');
    const chatSubmitBtn = document.getElementById('chat-submit-btn');

    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const prompt = promptInput.value.trim();
        if (!prompt) return;

        addMessage('user', escapeHTML(prompt));
        promptInput.value = '';
        chatSubmitBtn.disabled = true;
        chatSubmitBtn.textContent = 'Thinking...';

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: prompt })
            });

            if (!response.ok) {
                const errText = await response.text() || 'Network response was not ok';
                throw new Error(errText);
            }

            const data = await response.json();
            handleAIResponse(data);

        } catch (error) {
            console.error('Fetch error:', error);
            addMessage('ai', 'Sorry, I encountered an error. The AI service might be down or misconfigured. (' + error.message + ')');
        } finally {
            chatSubmitBtn.disabled = false;
            chatSubmitBtn.textContent = 'Send';
        }
    });

    function addMessage(sender, htmlContent) {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'chat-message ' + sender;
        msgDiv.innerHTML = htmlContent;
        chatMessages.appendChild(msgDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/[&<>"']/g, function(m) {
            return {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            }[m];
        });
    }

   function handleAIResponse(data) {
    let aiHTML = '';

    if (data.type === 'counseling') {
        // Handle object content for counseling
        if (typeof data.content === 'object' && data.content.message) {
            aiHTML = escapeHTML(data.content.message);
            
            if (data.content.showForm) {
                aiHTML += '<div style="margin-top: 1rem; padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 10px;">';
                aiHTML += '<h4 style="margin-bottom: 1rem;">Quick Consultation Booking</h4>';
                aiHTML += '<form onsubmit="handleQuickConsult(event); return false;">';
                aiHTML += '<div style="margin-bottom: 0.75rem;">';
                aiHTML += '<input type="text" placeholder="Your Name" required style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.2); border-radius: 5px; color: white;">';
                aiHTML += '</div>';
                aiHTML += '<div style="margin-bottom: 0.75rem;">';
                aiHTML += '<input type="email" placeholder="Your Email" required style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.2); border-radius: 5px; color: white;">';
                aiHTML += '</div>';
                aiHTML += '<div style="margin-bottom: 0.75rem;">';
                aiHTML += '<textarea placeholder="Brief description of your needs" rows="3" required style="width: 100%; padding: 0.5rem; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.2); border-radius: 5px; color: white;"></textarea>';
                aiHTML += '</div>';
                aiHTML += '<button type="submit" class="btn" style="width: 100%;">Submit Request</button>';
                aiHTML += '</form>';
                aiHTML += '</div>';
            }
            aiHTML += '<br><br>Or <a href="/counseling" style="color: #667eea;">view full booking form →</a>';
        } else {
            aiHTML = escapeHTML(data.content);
        }
    
    } else if (data.type === 'places') {
        // Handle object content for places
        if (typeof data.content === 'object') {
            if (data.content.message) {
                aiHTML = escapeHTML(data.content.message);
            }
            
            if (data.content.places && Array.isArray(data.content.places) && data.content.places.length > 0) {
                aiHTML += '<div style="margin-top: 1rem;">';
                data.content.places.forEach(function(place) {
                    aiHTML += '<div class="place-card" style="margin-top: 1rem; background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 10px; cursor: pointer; transition: all 0.3s;" onclick="window.location.href=\'/place/' + place.ID + '\'">';
                    aiHTML += '<h3 style="color: #667eea; margin-bottom: 0.5rem;">' + escapeHTML(place.Title) + '</h3>';
                    aiHTML += '<div style="font-size: 0.9rem; color: #a0a0a0; margin-bottom: 0.5rem;">';
                    aiHTML += '<span>📍 ' + escapeHTML(place.Category) + '</span> | ';
                    aiHTML += '<span>by ' + escapeHTML(place.SubmittedByUsername) + '</span>';
                    aiHTML += '</div>';
                    aiHTML += '<p style="margin-bottom: 0.75rem;">' + escapeHTML(place.Description || 'No description available') + '</p>';
                    aiHTML += '<div style="display: flex; gap: 1rem;">';
                    aiHTML += '<a href="/place/' + place.ID + '" style="color: #667eea; text-decoration: none;">View Details →</a>';
                    aiHTML += '<a href="' + escapeHTML(place.GoogleMapsLink) + '" target="_blank" style="color: #667eea; text-decoration: none;" onclick="event.stopPropagation();">Google Maps →</a>';
                    aiHTML += '</div>';
                    aiHTML += '</div>';
                });
                aiHTML += '</div>';
                aiHTML += '<br><a href="/places" style="color: #667eea;">Browse all places →</a>';
            } else {
                aiHTML += '<br><a href="/places" style="color: #667eea;">Browse all places →</a>';
            }
        } else if (Array.isArray(data.content) && data.content.length > 0) {
            // Handle legacy array format
            aiHTML = 'Here are some places I found for you:';
            data.content.forEach(function(place) {
                aiHTML += '<div class="place-card" style="margin-top: 1rem; background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 10px;">';
                aiHTML += '<h3 style="color: white;">' + escapeHTML(place.Title) + '</h3>';
                aiHTML += '<div class="place-card-meta" style="font-size: 0.9rem;">';
                aiHTML += 'By <strong>' + escapeHTML(place.SubmittedByUsername) + '</strong> | <span>' + escapeHTML(place.Category) + '</span>';
                aiHTML += '</div>';
                aiHTML += '<p class="place-card-desc" style="margin-top: 0.5rem;">' + escapeHTML(place.Description) + '</p>';
                aiHTML += '<a href="/place/' + place.ID + '" style="color: #667eea; text-decoration: none; font-weight: 600;">View Details →</a>';
                aiHTML += '</div>';
            });
        } else {
            aiHTML = escapeHTML(data.content.toString());
        }
    } else {
        // Handle "other" type
        if (typeof data.content === 'object' && data.content.message) {
            aiHTML = escapeHTML(data.content.message);
        } else {
            aiHTML = escapeHTML(data.content.toString());
        }
    }

    addMessage('ai', aiHTML);
}

// Add this new function right after handleAIResponse
function handleQuickConsult(event) {
    event.preventDefault();
    alert('Consultation request submitted! (This is a demo - implement actual submission)');
    addMessage('user', 'I submitted a consultation request');
    addMessage('ai', 'Thank you! Your consultation request has been received. Abel Tattersall will contact you soon at the email you provided.');
    return false;
}
</script>
{{end}}

{{define "counseling"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1>Book an Appointment</h1>
        <p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
            Schedule a consultation with Abel Tattersall for professional consulting services.
        </p>

        <div id="counseling-message" style="display: none; padding: 1rem; border-radius: 10px; margin-bottom: 1rem;"></div>

        <form id="counseling-form">
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" required placeholder="Your Full Name">
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label for="date">Preferred Date</label>
                <input type="date" id="date" name="date" required>
            </div>
            <div class="form-group">
                <label for="message">Reason for Appointment</label>
                <textarea id="message" name="message" rows="4" placeholder="Briefly describe your needs..."></textarea>
            </div>
            <button type="submit" class="btn">Submit Request</button>
        </form>
    </div>
</div>

<script>
document.getElementById('counseling-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(e.target);
    const messageDiv = document.getElementById('counseling-message');
    const submitBtn = e.target.querySelector('button[type="submit"]');

    // Disable submit button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting...';

    try {
        const response = await fetch('/api/counseling/submit', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        // Show message
        messageDiv.style.display = 'block';
        if (data.status === 'success' || data.status === 'partial') {
            messageDiv.style.backgroundColor = 'rgba(76, 175, 80, 0.2)';
            messageDiv.style.border = '1px solid rgba(76, 175, 80, 0.5)';
            messageDiv.textContent = data.message;
            e.target.reset();
        } else {
            messageDiv.style.backgroundColor = 'rgba(244, 67, 54, 0.2)';
            messageDiv.style.border = '1px solid rgba(244, 67, 54, 0.5)';
            messageDiv.textContent = data.message || 'An error occurred. Please try again.';
        }
    } catch (error) {
        messageDiv.style.display = 'block';
        messageDiv.style.backgroundColor = 'rgba(244, 67, 54, 0.2)';
        messageDiv.style.border = '1px solid rgba(244, 67, 54, 0.5)';
        messageDiv.textContent = 'An error occurred. Please try again later.';
    } finally {
        // Re-enable submit button
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Request';
    }
});
</script>
{{end}}

{{define "forgot_password"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1>Forgot Password</h1>
        <p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
            Enter your email address and we'll send you a password reset link.
        </p>

        <form method="POST" action="/forgot-password">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
            </div>
            <button type="submit" class="btn">Send Reset Link</button>
        </form>

        <p style="text-align: center; margin-top: 1.5rem;">
            <a href="/login" style="color: var(--text-gray);">Back to Login</a>
        </p>
    </div>
</div>
{{end}}

{{define "reset_password"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1>Reset Password</h1>
        <p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
            Enter your new password below.
        </p>

        {{if .Data}}
        <form method="POST" action="/reset-password?token={{index .Data "token"}}">
            <div class="form-group">
                <label for="password">New Password</label>
                <input type="password" id="password" name="password" required minlength="6" placeholder="At least 6 characters">
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required placeholder="Re-enter your password">
            </div>
            <button type="submit" class="btn">Reset Password</button>
        </form>
        {{end}}
    </div>
</div>
{{end}}

{{define "change_password"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1>Change Password</h1>
        <p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
            Update your account password.
        </p>

        {{if .Data}}
            {{if .Data.Message}}
            <div style="padding: 1rem; border-radius: 10px; margin-bottom: 1rem; background-color: rgba(244, 67, 54, 0.2); border: 1px solid rgba(244, 67, 54, 0.5);">
                {{.Data.Message}}
            </div>
            {{end}}
        {{end}}

        <form method="POST" action="/change-password">
            <div class="form-group">
                <label for="current_password">Current Password</label>
                <input type="password" id="current_password" name="current_password" required>
            </div>
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" required minlength="6" placeholder="At least 6 characters">
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn">Change Password</button>
        </form>

        <p style="text-align: center; margin-top: 1.5rem;">
            <a href="/dashboard" style="color: var(--text-gray);">Back to Dashboard</a>
        </p>
    </div>
</div>
{{end}}

{{define "delete_account"}}
{{template "layout" .}}
<div class="container">
    <div class="form-card">
        <h1 style="color: #f44336;">Delete Account</h1>
        <p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
            This action cannot be undone. All your data will be permanently deleted.
        </p>

        {{if .Data}}
            {{if .Data.Message}}
            <div style="padding: 1rem; border-radius: 10px; margin-bottom: 1rem; background-color: rgba(244, 67, 54, 0.2); border: 1px solid rgba(244, 67, 54, 0.5);">
                {{.Data.Message}}
            </div>
            {{end}}
        {{end}}

        <form method="POST" action="/delete-account" onsubmit="return confirm('Are you absolutely sure? This cannot be undone!');">
            <div class="form-group">
                <label for="password">Confirm Your Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirmation">Type "DELETE" to confirm</label>
                <input type="text" id="confirmation" name="confirmation" required placeholder="Type DELETE">
            </div>
            <button type="submit" class="btn" style="background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);">
                Delete My Account
            </button>
        </form>

        <p style="text-align: center; margin-top: 1.5rem;">
            <a href="/dashboard" style="color: var(--text-gray);">Cancel and go back</a>
        </p>
    </div>
</div>
{{end}}
`