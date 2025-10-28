package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"golang.org/x/crypto/bcrypt"
)

// --- CONFIGURATION ---
// WARNING: Do NOT hardcode secrets in a real application.
// Load from environment variables.
const (
	// SMTP settings from your request
	smtpHost     = "mail.needgreatersglobal.com"
	smtpPort     = "587" // Common TLS port
	smtpEmail    = "endrig@needgreatersglobal.com"
	smtpPassword = "Assembly3637997Ab,"
	// Session key - MUST be kept secret and should be a long, random string.
	sessionKey = "a-very-secret-key-32-bytes-long"
	// Base URL of your application (for email links)
	baseURL = "http://localhost:8080"
)
// --- GLOBALS ---
var (
	db    *sql.DB               // Database connection pool
	store *sessions.CookieStore // Session store
	tpl   *template.Template    // HTML templates
)
// --- MODELS ---
// User defines the user model
type User struct {
	ID                int
	Username          string
	Email             string
	PasswordHash      string
	IsVerified        bool
	IsAdmin           bool
	VerificationToken sql.NullString // Can be NULL in DB
	TokenExpiry       sql.NullTime   // Can be NULL in DB
}
// AdminPageData holds data for the admin template
type AdminPageData struct {
	CurrentUser User
	Users       []User
	Message     string
	Error       string
}
// DashboardPageData holds data for the dashboard template
type DashboardPageData struct {
	CurrentUser User
}
// MessagePageData holds data for the general message template
type MessagePageData struct {
	Title   string
	Message string
}
// PageBundle is a wrapper to pass data to the layout template
type PageBundle struct {
	PageName    string
	Data        interface{}
	CurrentUser User // Add CurrentUser here for the nav template
}
// --- MAIN FUNCTION ---
func main() {
	var err error
	// 1. Initialize Database
	db, err = initDB("./users.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	log.Println("Database initialized.")
	// 2. Initialize Session Store
	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		// Secure: true, // Uncomment in production (requires HTTPS)
	}
	// 3. Parse Templates
	tpl = template.Must(template.New("main").Parse(allTemplates))
	// 4. Setup Routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/maps", mapsHandler) // --- CHANGE 1: ADDED MAPS ROUTE ---
	// Authenticated routes
	http.Handle("/dashboard", requireAuth(http.HandlerFunc(dashboardHandler)))
	http.Handle("/admin", requireAuth(requireAdmin(http.HandlerFunc(adminHandler))))
	// 5. Start Server
	log.Println("Starting server on " + baseURL + " ...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
// --- DATABASE ---
func initDB(filepath string) (*sql.DB, error) {
	var err error // Declare err variable
	// Use '=' to assign to the global 'db' variable, not ':=_
	db, err = sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}
	// Create users table
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		is_verified BOOLEAN NOT_NULL DEFAULT 0,
		is_admin BOOLEAN NOT_NULL DEFAULT 0,
		verification_token TEXT,
		token_expiry DATETIME
	);`
	// Use '=' to assign to the already declared 'err'
	if _, err = db.Exec(createTableSQL); err != nil {
		return nil, err
	}
	// Create a default admin user if one doesn't exist
	// This is now safe because the global 'db' is initialized
	createAdmin()
	return db, nil
}
func createAdmin() {
	// Check if admin user already exists
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE email = 'admin@example.com'").Scan(&email)
	if err == nil {
		log.Println("Admin user already exists.")
		return // Admin already exists
	}
	if err != sql.ErrNoRows {
		log.Println("Error checking for admin user:", err)
		return
	}
	// Admin doesn't exist, create one
	log.Println("Creating default admin user (admin@example.com / password123)")
	hashedPassword, err := hashPassword("password123")
	if err != nil {
		log.Println("Failed to hash admin password:", err)
		return
	}
	_, err = db.Exec(`
		INSERT INTO users (username, email, password_hash, is_verified, is_admin)
		VALUES ('admin', 'admin@example.com', ?, 1, 1)
	`, hashedPassword)
	if err != nil {
		log.Println("Failed to create admin user:", err)
	} else {
		log.Println("Default admin user created.")
		log.Println("--- ADMIN LOGIN ---")
		log.Println("Email: admin@example.com")
		log.Println("Password: password123")
		log.Println("-------------------")
	}
}
// --- HANDLERS ---
// homeHandler shows the home page (login/register links)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get user from session for nav bar, but don't require auth
	user, _ := getUserFromSession(r)
	renderTemplate(w, "home", nil, user)
}
// registerHandler handles user registration (GET and POST)
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get user from session for nav bar
	user, _ := getUserFromSession(r)
	if r.Method == http.MethodGet {
		renderTemplate(w, "register", nil, user)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if username == "" || email == "" || password == "" {
			renderTemplate(w, "register", map[string]string{"Error": "All fields are required"}, user)
			return
		}
		// Check if email or username is already taken
		var exists int
		err := db.QueryRow("SELECT 1 FROM users WHERE username = ? OR email = ?", username, email).Scan(&exists)
		if err != sql.ErrNoRows && err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if exists == 1 {
			renderTemplate(w, "register", map[string]string{"Error": "Username or email already taken"}, user)
			return
		}
		// Hash password
		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		// Generate verification token
		token, err := generateToken()
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		expiry := time.Now().Add(24 * time.Hour)
		// Insert user into DB
		_, err = db.Exec(`
			INSERT INTO users (username, email, password_hash, verification_token, token_expiry)
			VALUES (?, ?, ?, ?, ?)
		`, username, email, hashedPassword, token, expiry)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		// Send verification email
		verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
		err = sendVerificationEmail(email, verificationLink)
		if err != nil {
			log.Println("Failed to send verification email:", err)
			// Non-fatal error for user, but we should log it
			http.Error(w, "Failed to send verification email, but user was created.", http.StatusInternalServerError)
			return
		}
		// Show success message
		renderTemplate(w, "message", MessagePageData{
			Title:   "Registration Successful",
			Message: "Please check your email to verify your account.",
		}, user) // Pass user for nav
	}
}
// loginHandler handles user login (GET and POST)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get user from session for nav bar
	user, _ := getUserFromSession(r)
	if r.Method == http.MethodGet {
		renderTemplate(w, "login", nil, user)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		// Find user by email
		var dbUser User // Renamed to avoid conflict
		err := db.QueryRow("SELECT id, username, email, password_hash, is_verified, is_admin FROM users WHERE email = ?", email).
			Scan(&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.PasswordHash, &dbUser.IsVerified, &dbUser.IsAdmin)
		if err == sql.ErrNoRows {
			renderTemplate(w, "login", map[string]string{"Error": "Invalid email or password"}, user)
			return
		}
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		// Check password
		if !checkPasswordHash(password, dbUser.PasswordHash) {
			renderTemplate(w, "login", map[string]string{"Error": "Invalid email or password"}, user)
			return
		}
		// Check if verified
		if !dbUser.IsVerified {
			renderTemplate(w, "login", map[string]string{"Error": "Please verify your email before logging in."}, user)
			return
		}
		// Create session
		session, _ := store.Get(r, "user-session")
		session.Values["user_id"] = dbUser.ID
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}
		// Redirect to appropriate dashboard
		if dbUser.IsAdmin {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		}
	}
}
// logoutHandler clears the user session
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	session.Values["user_id"] = nil
	session.Options.MaxAge = -1 // Delete the cookie
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
// verifyHandler handles the email verification link
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get user from session for nav bar
	user, _ := getUserFromSession(r)
	token := r.URL.Query().Get("token")
	if token == "" {
		renderTemplate(w, "message", MessagePageData{Title: "Error", Message: "Invalid verification token."}, user)
		return
	}
	var expiry sql.NullTime
	var userID int
	err := db.QueryRow("SELECT id, token_expiry FROM users WHERE verification_token = ?", token).
		Scan(&userID, &expiry)
	if err == sql.ErrNoRows {
		renderTemplate(w, "message", MessagePageData{Title: "Error", Message: "Invalid verification token."}, user)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// Check if token expired
	if !expiry.Valid || time.Now().After(expiry.Time) {
		// Optionally: delete user or allow resend
		renderTemplate(w, "message", MessagePageData{Title: "Error", Message: "Verification token has expired."}, user)
		return
	}
	// Activate user
	_, err = db.Exec(`
		UPDATE users
		SET is_verified = 1, verification_token = NULL, token_expiry = NULL
		WHERE id = ?
	`, userID)
	if err != nil {
		http.Error(w, "Failed to verify user", http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "message", MessagePageData{
		Title:   "Success",
		Message: "Your email has been verified! You can now log in.",
	}, user)
}
// --- CHANGE 2: ADDED MAPS HANDLER ---
// mapsHandler shows the google map page
func mapsHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get user from session for nav bar, but don't require auth
	user, _ := getUserFromSession(r)
	renderTemplate(w, "maps", nil, user)
}
// dashboardHandler shows the user's personal dashboard
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User) // Get user from context (set by middleware)
	data := DashboardPageData{
		CurrentUser: user,
	}
	renderTemplate(w, "dashboard", data, user)
}
// adminHandler shows the admin management portal
func adminHandler(w http.ResponseWriter, r *http.Request) {
	currentUser := r.Context().Value("user").(User) // Get admin user from context
	pageData := AdminPageData{
		CurrentUser: currentUser,
	}
	// Handle form submissions for user management
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		userIDToManage := r.FormValue("user_id")
		// Prevent admin from modifying their own account this way
		if userIDToManage == fmt.Sprintf("%d", currentUser.ID) {
			pageData.Error = "You cannot modify your own account from this panel."
		} else {
			switch action {
			case "make_admin":
				_, err := db.Exec("UPDATE users SET is_admin = 1 WHERE id = ?", userIDToManage)
				if err != nil {
					pageData.Error = "Failed to make user admin."
				} else {
					pageData.Message = "User permissions updated."
				}
			case "remove_admin":
				_, err := db.Exec("UPDATE users SET is_admin = 0 WHERE id = ?", userIDToManage)
				if err != nil {
					pageData.Error = "Failed to remove admin rights."
				} else {
					pageData.Message = "User permissions updated."
				}
			case "delete_user":
				_, err := db.Exec("DELETE FROM users WHERE id = ?", userIDToManage)
				if err != nil {
					pageData.Error = "Failed to delete user."
				} else {
					pageData.Message = "User deleted."
				}
			}
		}
	}
	// Fetch all users to display
	rows, err := db.Query("SELECT id, username, email, is_verified, is_admin FROM users ORDER BY id")
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin); err != nil {
			log.Println("Error scanning user row:", err)
			continue
		}
		users = append(users, u)
	}
	pageData.Users = users
	renderTemplate(w, "admin", pageData, currentUser)
}
// --- MIDDLEWARE ---
// requireAuth middleware checks if a user is logged in
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "user-session")
		userID, ok := session.Values["user_id"].(int)
		if !ok || userID == 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Get user from DB and add to context
		var user User
		err := db.QueryRow("SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?", userID).
			Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)
		if err != nil {
			// User deleted or DB error, clear session
			session.Values["user_id"] = nil
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Add user to request context
		ctx := r.Context()
		ctxWithUser := context.WithValue(ctx, "user", user)
		r = r.WithContext(ctxWithUser)
		next.ServeHTTP(w, r)
	})
}
// requireAdmin middleware checks if a logged-in user is an admin
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value("user").(User)
		if !ok || !user.IsAdmin {
			// User is not an admin, redirect to regular dashboard
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
// --- UTILITIES ---
// getUserFromSession is a helper to get user info without requiring auth
// (New function)
func getUserFromSession(r *http.Request) (User, error) {
	var user User
	session, _ := store.Get(r, "user-session")
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		return user, fmt.Errorf("no user in session")
	}
	// Get user from DB
	err := db.QueryRow("SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)
	if err != nil {
		return user, err
	}
	return user, nil
}
// renderTemplate is a helper to render HTML templates
func renderTemplate(w http.ResponseWriter, name string, data interface{}, user User) {
	bundle := PageBundle{
		PageName:    name,
		Data:        data,
		CurrentUser: user, // Pass the user for the nav bar
	}
	err := tpl.ExecuteTemplate(w, "layout", bundle) // Always execute layout
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}
// hashPassword generates a bcrypt hash for a password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
// checkPasswordHash compares a plain-text password with a hash
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
// generateToken creates a secure, random token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
// sendVerificationEmail sends an email using the configured SMTP settings
// sendVerificationEmail sends an email using the configured SMTP settings
func sendVerificationEmail(to, verificationLink string) error {
	// SMTP server authentication
	auth := smtp.PlainAuth("", smtpEmail, smtpPassword, smtpHost)
	// --- START FIX ---
	// We must manually create the email headers
	// in the message body
	headers := make(map[string]string)
	headers["From"] = smtpEmail // e.g., "Your App <no-reply@example.com>"
	headers["To"] = to
	headers["Subject"] = "Verify Your Account"
	headers["MIME-version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""
	// Assemble the message headers
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" // This empty line separates headers from the body
	// HTML body
	body := fmt.Sprintf(`
	<html>
	<body>
		<h2>Welcome!</h2>
		<p>Thank you for registering. Please click the link below to verify your email address:</p>
		<p><a href="%s">Verify My Account</a></p>
		<p>This link will expire in 24 hours.</p>
	</body>
	</html>
	`, verificationLink)
	// Combine headers and body
	msg := []byte(message + body)
	// --- END FIX ---
	// Send email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpEmail, []string{to}, msg)
	if err != nil {
		// Log the full error for debugging
		log.Printf("smtp.SendMail error: %v", err)
		return err
	}
	return nil
}
// --- EMBEDDED TEMPLATES ---
// All HTML templates are defined here
const allTemplates = `
{{define "layout"}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>NGG Consulting - Business Excellence & Kosovo Discovery</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		
		:root {
			--primary: #1a1a2e;
			--secondary: #16213e;
			--accent: #0f3460;
			--highlight: #e94560;
			--text-light: #ffffff;
			--text-gray: #94a3b8;
			--gold: #ffd700;
			--gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			--gradient-secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
			--gradient-dark: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%);
		}
		
		body { 
			font-family: 'Inter', sans-serif; 
			line-height: 1.6; 
			background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #0f3460 100%);
			color: var(--text-light);
			min-height: 100vh;
			overflow-x: hidden;
		}

		/* Animated background */
		body::before {
			content: '';
			position: fixed;
			top: 0;
			left: 0;
			width: 100%;
			height: 100%;
			background-image: 
				radial-gradient(circle at 20% 50%, rgba(233, 69, 96, 0.1) 0%, transparent 50%),
				radial-gradient(circle at 80% 80%, rgba(102, 126, 234, 0.1) 0%, transparent 50%),
				radial-gradient(circle at 40% 20%, rgba(245, 87, 108, 0.1) 0%, transparent 50%);
			z-index: -1;
			animation: float 20s ease-in-out infinite;
		}

		@keyframes float {
			0%, 100% { transform: translateY(0) rotate(0deg); }
			50% { transform: translateY(-20px) rotate(2deg); }
		}

		/* Modern Navigation */
		.navbar {
			background: rgba(26, 26, 46, 0.95);
			backdrop-filter: blur(20px);
			padding: 1rem 0;
			position: fixed;
			width: 100%;
			top: 0;
			z-index: 1000;
			box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
			border-bottom: 1px solid rgba(255, 255, 255, 0.1);
		}

		.nav-container {
			max-width: 1400px;
			margin: 0 auto;
			padding: 0 2rem;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.logo {
			font-size: 1.8rem;
			font-weight: 800;
			background: var(--gradient-primary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			text-decoration: none;
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}

		.logo span {
			font-size: 0.9rem;
			font-weight: 400;
			color: var(--text-gray);
			-webkit-text-fill-color: var(--text-gray);
		}

		nav ul {
			list-style: none;
			display: flex;
			gap: 2rem;
			align-items: center;
		}

		nav a {
			color: var(--text-light);
			text-decoration: none;
			font-weight: 500;
			transition: all 0.3s ease;
			position: relative;
			padding: 0.5rem 1rem;
		}

		nav a::after {
			content: '';
			position: absolute;
			bottom: 0;
			left: 50%;
			width: 0;
			height: 2px;
			background: var(--gradient-primary);
			transition: all 0.3s ease;
			transform: translateX(-50%);
		}

		nav a:hover::after {
			width: 100%;
		}

		.nav-btn {
			background: var(--gradient-primary);
			color: white !important;
			padding: 0.6rem 1.5rem !important;
			border-radius: 50px;
			font-weight: 600;
			transition: all 0.3s ease;
			box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
		}

		.nav-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 6px 25px rgba(102, 126, 234, 0.4);
		}

		/* Main container */
		.container {
			max-width: 1400px;
			margin: 0 auto;
			padding: 2rem;
			margin-top: 80px;
		}

		/* Hero Section */
		.hero {
			min-height: calc(100vh - 80px);
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 4rem 2rem;
			position: relative;
			overflow: hidden;
		}

		.hero-content {
			max-width: 1400px;
			width: 100%;
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 4rem;
			align-items: center;
			z-index: 2;
		}

		.hero-text h1 {
			font-size: clamp(2.5rem, 5vw, 4.5rem);
			font-weight: 900;
			line-height: 1.1;
			margin-bottom: 1.5rem;
			background: linear-gradient(135deg, #fff 0%, #667eea 50%, #764ba2 100%);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			animation: gradient 3s ease infinite;
		}

		@keyframes gradient {
			0%, 100% { background-position: 0% 50%; }
			50% { background-position: 100% 50%; }
		}

		.hero-text p {
			font-size: 1.2rem;
			color: var(--text-gray);
			margin-bottom: 2rem;
			line-height: 1.8;
		}

		.hero-buttons {
			display: flex;
			gap: 1rem;
			flex-wrap: wrap;
		}

		.btn-primary, .btn-secondary {
			padding: 1rem 2.5rem;
			border-radius: 50px;
			font-weight: 600;
			text-decoration: none;
			transition: all 0.3s ease;
			display: inline-block;
			font-size: 1.1rem;
		}

		.btn-primary {
			background: var(--gradient-primary);
			color: white;
			box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
		}

		.btn-primary:hover {
			transform: translateY(-3px);
			box-shadow: 0 8px 30px rgba(102, 126, 234, 0.5);
		}

		.btn-secondary {
			background: transparent;
			color: white;
			border: 2px solid rgba(255, 255, 255, 0.3);
			backdrop-filter: blur(10px);
		}

		.btn-secondary:hover {
			background: rgba(255, 255, 255, 0.1);
			border-color: rgba(255, 255, 255, 0.5);
		}

		.hero-image {
			position: relative;
			height: 500px;
			border-radius: 20px;
			overflow: hidden;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
		}

		.hero-image img {
			width: 100%;
			height: 100%;
			object-fit: cover;
		}

		/* Services Section */
		.services {
			padding: 5rem 2rem;
			background: rgba(26, 26, 46, 0.5);
			backdrop-filter: blur(10px);
			margin: 2rem 0;
			border-radius: 30px;
		}

		.services h2 {
			text-align: center;
			font-size: 3rem;
			margin-bottom: 1rem;
			background: var(--gradient-primary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.services-subtitle {
			text-align: center;
			color: var(--text-gray);
			font-size: 1.2rem;
			margin-bottom: 4rem;
		}

		.services-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
			gap: 2rem;
			margin-top: 3rem;
		}

		.service-card {
			background: linear-gradient(135deg, rgba(26, 26, 46, 0.9) 0%, rgba(15, 52, 96, 0.9) 100%);
			padding: 2.5rem;
			border-radius: 20px;
			transition: all 0.3s ease;
			border: 1px solid rgba(255, 255, 255, 0.1);
			position: relative;
			overflow: hidden;
		}

		.service-card::before {
			content: '';
			position: absolute;
			top: -50%;
			right: -50%;
			width: 200%;
			height: 200%;
			background: radial-gradient(circle, rgba(102, 126, 234, 0.1) 0%, transparent 70%);
			transition: all 0.5s ease;
		}

		.service-card:hover::before {
			top: -25%;
			right: -25%;
		}

		.service-card:hover {
			transform: translateY(-10px);
			box-shadow: 0 20px 40px rgba(102, 126, 234, 0.3);
			border-color: rgba(102, 126, 234, 0.5);
		}

		.service-icon {
			width: 60px;
			height: 60px;
			background: var(--gradient-primary);
			border-radius: 15px;
			display: flex;
			align-items: center;
			justify-content: center;
			font-size: 1.8rem;
			margin-bottom: 1.5rem;
		}

		.service-card h3 {
			font-size: 1.5rem;
			margin-bottom: 1rem;
			color: var(--text-light);
		}

		.service-card p {
			color: var(--text-gray);
			line-height: 1.8;
		}

		/* Community Section */
		.community {
			padding: 5rem 2rem;
			background: linear-gradient(135deg, rgba(15, 52, 96, 0.3) 0%, rgba(26, 26, 46, 0.3) 100%);
			backdrop-filter: blur(10px);
			border-radius: 30px;
			margin: 2rem 0;
		}

		.community h2 {
			text-align: center;
			font-size: 3rem;
			margin-bottom: 3rem;
			background: var(--gradient-secondary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.map-container {
			background: rgba(26, 26, 46, 0.8);
			border-radius: 20px;
			padding: 2rem;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
		}

		.map-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 2rem;
		}

		.map-header h3 {
			font-size: 1.8rem;
			color: var(--text-light);
		}

		.map-iframe {
			width: 100%;
			height: 600px;
			border-radius: 15px;
			border: none;
		}

		/* Forms Styling */
		.form-card {
			max-width: 500px;
			margin: 4rem auto;
			padding: 3rem;
			background: linear-gradient(135deg, rgba(26, 26, 46, 0.95) 0%, rgba(15, 52, 96, 0.95) 100%);
			backdrop-filter: blur(20px);
			border-radius: 20px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
			border: 1px solid rgba(255, 255, 255, 0.1);
		}

		.form-card h1 {
			text-align: center;
			font-size: 2.5rem;
			margin-bottom: 2rem;
			background: var(--gradient-primary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.form-group {
			margin-bottom: 1.5rem;
		}

		.form-group label {
			display: block;
			margin-bottom: 0.5rem;
			color: var(--text-gray);
			font-weight: 500;
			font-size: 0.95rem;
			text-transform: uppercase;
			letter-spacing: 1px;
		}

		.form-group input {
			width: 100%;
			padding: 1rem;
			background: rgba(255, 255, 255, 0.05);
			border: 1px solid rgba(255, 255, 255, 0.1);
			border-radius: 10px;
			color: white;
			font-size: 1rem;
			transition: all 0.3s ease;
		}

		.form-group input:focus {
			outline: none;
			border-color: rgba(102, 126, 234, 0.5);
			background: rgba(255, 255, 255, 0.08);
			box-shadow: 0 0 20px rgba(102, 126, 234, 0.2);
		}

		.btn {
			width: 100%;
			padding: 1rem;
			background: var(--gradient-primary);
			color: white;
			border: none;
			border-radius: 50px;
			font-size: 1.1rem;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.3s ease;
			box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
			text-transform: uppercase;
			letter-spacing: 1px;
		}

		.btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 8px 30px rgba(102, 126, 234, 0.5);
		}

		.alert-error {
			background: rgba(233, 69, 96, 0.1);
			border: 1px solid rgba(233, 69, 96, 0.3);
			color: #ff6b6b;
			padding: 1rem;
			border-radius: 10px;
			margin-bottom: 1.5rem;
			text-align: center;
		}

		.alert-success {
			background: rgba(46, 204, 113, 0.1);
			border: 1px solid rgba(46, 204, 113, 0.3);
			color: #2ecc71;
			padding: 1rem;
			border-radius: 10px;
			margin-bottom: 1.5rem;
			text-align: center;
		}

		/* Dashboard Styling */
		.dashboard-card {
			background: linear-gradient(135deg, rgba(26, 26, 46, 0.95) 0%, rgba(15, 52, 96, 0.95) 100%);
			backdrop-filter: blur(20px);
			padding: 3rem;
			border-radius: 20px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
			border: 1px solid rgba(255, 255, 255, 0.1);
			margin-top: 2rem;
		}

		.dashboard-card h1 {
			font-size: 2.5rem;
			margin-bottom: 2rem;
			background: var(--gradient-primary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.user-info {
			background: rgba(255, 255, 255, 0.05);
			padding: 2rem;
			border-radius: 15px;
			margin-top: 2rem;
		}

		.user-info ul {
			list-style: none;
			padding: 0;
		}

		.user-info li {
			padding: 1rem;
			border-bottom: 1px solid rgba(255, 255, 255, 0.1);
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.user-info li:last-child {
			border-bottom: none;
		}

		.user-info strong {
			color: var(--text-gray);
			text-transform: uppercase;
			font-size: 0.9rem;
			letter-spacing: 1px;
		}

		/* Admin Table */
		.admin-table {
			width: 100%;
			background: rgba(26, 26, 46, 0.95);
			border-radius: 15px;
			overflow: hidden;
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
			margin-top: 2rem;
		}

		table {
			width: 100%;
			border-collapse: collapse;
		}

		th {
			background: var(--gradient-primary);
			color: white;
			padding: 1rem;
			text-align: left;
			font-weight: 600;
			text-transform: uppercase;
			font-size: 0.9rem;
			letter-spacing: 1px;
		}

		td {
			padding: 1rem;
			border-bottom: 1px solid rgba(255, 255, 255, 0.05);
			color: var(--text-light);
		}

		tr:hover {
			background: rgba(255, 255, 255, 0.03);
		}

		.action-form {
			display: inline-block;
			margin-right: 0.5rem;
		}

		.action-form button {
			padding: 0.5rem 1rem;
			border: none;
			border-radius: 8px;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.3s ease;
			font-size: 0.85rem;
			text-transform: uppercase;
			letter-spacing: 0.5px;
		}

		.btn-admin {
			background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
			color: white;
		}

		.btn-admin:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 15px rgba(240, 147, 251, 0.4);
		}

		.btn-delete {
			background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
			color: white;
		}

		.btn-delete:hover {
			transform: translateY(-2px);
			box-shadow: 0 4px 15px rgba(255, 107, 107, 0.4);
		}

		/* Responsive */
		@media (max-width: 768px) {
			.hero-content {
				grid-template-columns: 1fr;
			}
			
			.services-grid {
				grid-template-columns: 1fr;
			}
			
			nav ul {
				flex-direction: column;
				gap: 1rem;
			}
			
			.hero-text h1 {
				font-size: 2rem;
			}
		}

		/* Footer */
		.footer {
			background: rgba(26, 26, 46, 0.95);
			padding: 3rem 2rem 1rem;
			margin-top: 5rem;
			border-top: 1px solid rgba(255, 255, 255, 0.1);
		}

		.footer-content {
			max-width: 1400px;
			margin: 0 auto;
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
			gap: 3rem;
		}

		.footer-section h3 {
			color: var(--text-light);
			margin-bottom: 1rem;
			font-size: 1.2rem;
		}

		.footer-section p,
		.footer-section a {
			color: var(--text-gray);
			text-decoration: none;
			line-height: 1.8;
			transition: color 0.3s ease;
		}

		.footer-section a:hover {
			color: var(--text-light);
		}

		.footer-bottom {
			text-align: center;
			padding: 2rem 0 1rem;
			margin-top: 2rem;
			border-top: 1px solid rgba(255, 255, 255, 0.1);
			color: var(--text-gray);
		}

		/* Stats Section */
		.stats {
			padding: 3rem 2rem;
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 2rem;
			margin: 3rem 0;
		}

		.stat-card {
			text-align: center;
			background: rgba(255, 255, 255, 0.05);
			padding: 2rem;
			border-radius: 15px;
			border: 1px solid rgba(255, 255, 255, 0.1);
		}

		.stat-number {
			font-size: 3rem;
			font-weight: 800;
			background: var(--gradient-primary);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}

		.stat-label {
			color: var(--text-gray);
			margin-top: 0.5rem;
			text-transform: uppercase;
			letter-spacing: 1px;
			font-size: 0.9rem;
		}
	</style>
</head>
<body>
	{{template "nav" .}}
	{{if eq .PageName "home"}}
		{{template "home" .Data}}
	{{else if eq .PageName "register"}}
		{{template "register" .Data}}
	{{else if eq .PageName "login"}}
		{{template "login" .Data}}
	{{else if eq .PageName "dashboard"}}
		{{template "dashboard" .Data}}
	{{else if eq .PageName "admin"}}
		{{template "admin" .Data}}
	{{else if eq .PageName "message"}}
		{{template "message" .Data}}
	{{else if eq .PageName "maps"}}
		{{template "maps" .Data}}
	{{end}}
</body>
</html>
{{end}}

{{define "nav"}}
<nav class="navbar">
	<div class="nav-container">
		<a href="/" class="logo">
			NGG <span>Consulting</span>
		</a>
		<ul>
			<li><a href="/">Home</a></li>
			<li><a href="/#services">Services</a></li>
			<li><a href="/maps">Discover Kosovo</a></li>
			{{if .CurrentUser.ID}}
				<li><a href="/dashboard">Dashboard</a></li>
				{{if .CurrentUser.IsAdmin}}
					<li><a href="/admin">Admin</a></li>
				{{end}}
				<li><a href="/logout" class="nav-btn">Logout</a></li>
			{{else}}
				<li><a href="/login">Login</a></li>
				<li><a href="/register" class="nav-btn">Get Started</a></li>
			{{end}}
		</ul>
	</div>
</nav>
{{end}}

{{define "home"}}
<div class="hero">
	<div class="hero-content">
		<div class="hero-text">
			<h1>Empower Your Business with NGG Consulting</h1>
			<p>Expert consulting services in law, taxation, business growth, and IT solutions. Plus, discover the hidden gems of Kosovo through our vibrant community platform.</p>
			<div class="hero-buttons">
				<a href="/register" class="btn-primary">Start Your Journey</a>
				<a href="#services" class="btn-secondary">Explore Services</a>
			</div>
		</div>
		<div class="hero-image">
			<img src="https://images.unsplash.com/photo-1556761175-5973dc0f32e7?w=800&auto=format&fit=crop" alt="Business Consulting">
		</div>
	</div>
</div>

<div class="container">
	<div class="stats">
		<div class="stat-card">
			<div class="stat-number">500+</div>
			<div class="stat-label">Clients Served</div>
		</div>
		<div class="stat-card">
			<div class="stat-number">6</div>
			<div class="stat-label">Countries</div>
		</div>
		<div class="stat-card">
			<div class="stat-number">15+</div>
			<div class="stat-label">Years Experience</div>
		</div>
		<div class="stat-card">
			<div class="stat-number">100%</div>
			<div class="stat-label">Client Satisfaction</div>
		</div>
	</div>

	<div class="services" id="services">
		<h2>Our Premium Services</h2>
		<p class="services-subtitle">Comprehensive solutions for your business growth</p>
		
		<div class="services-grid">
			<div class="service-card">
				<div class="service-icon">§</div>
				<h3>Commercial & Corporate Law</h3>
				<p>Our strong partnership with dedicated auditors, skilled tax experts, and experienced management consultants allows us to assist you effectively with a wide range of important legal tasks and services.</p>
			</div>
			
			<div class="service-card">
				<div class="service-icon">∑</div>
				<h3>Accounting & Taxation</h3>
				<p>NGG Consulting finds the right solutions for clients in accounting and taxation using resources of qualified experts with many years of experience in this field.</p>
			</div>
			
			<div class="service-card">
				<div class="service-icon">↗</div>
				<h3>Business Consulting & Growth</h3>
				<p>International development or internal optimization of your business in four stages. Our services focus on the most important developmental issues and sustainability opportunities.</p>
			</div>
			
			<div class="service-card">
				<div class="service-icon">&lt;/&gt;</div>
				<h3>IT Outsourcing</h3>
				<p>Expanding your software development team? Consider our specialized nearshoring and offshoring services. We operate in 6 Western Balkan countries with top-tier talent.</p>
			</div>

			<div class="service-card">
				<div class="service-icon">◐</div>
				<h3>International Expansion</h3>
				<p>Navigate global markets with confidence. We provide comprehensive support for businesses looking to expand internationally, from market research to legal compliance.</p>
			</div>

			<div class="service-card">
				<div class="service-icon">◈</div>
				<h3>Digital Transformation</h3>
				<p>Transform your business for the digital age. From automation to cloud solutions, we help you leverage technology to increase efficiency and competitiveness.</p>
			</div>
		</div>
	</div>

	<div class="community">
		<h2>Discover Kosovo's Hidden Treasures</h2>
		<p style="text-align: center; color: var(--text-gray); margin-bottom: 3rem; font-size: 1.2rem;">
			Join our community to share and explore the most beautiful places in Kosovo. Connect with locals and travelers to uncover authentic experiences.
		</p>
		
		<div class="map-container">
			<div class="map-header">
				<h3>◉ Community-Curated Places</h3>
				<a href="/register" class="btn-primary" style="padding: 0.8rem 2rem;">Join Community</a>
			</div>
			<p style="color: var(--text-gray); margin-bottom: 2rem;">
				Share your favorite spots, leave reviews, and discover where other community members love to visit. From pristine nature to historic sites, explore Kosovo like never before.
			</p>
			<iframe class="map-iframe" src="https://www.google.com/maps/d/embed?mid=15kGHj7YZlrJZJgSFsfOPvS6ucMbH_RU&ehbc=2E312F" allowfullscreen="" loading="lazy"></iframe>
		</div>
	</div>
</div>

<div class="footer">
	<div class="footer-content">
		<div class="footer-section">
			<h3>NGG Consulting</h3>
			<p>Your trusted partner for business excellence and growth. Operating across Western Balkans with global reach.</p>
		</div>
		<div class="footer-section">
			<h3>Services</h3>
			<p><a href="#services">Corporate Law</a></p>
			<p><a href="#services">Accounting & Tax</a></p>
			<p><a href="#services">Business Consulting</a></p>
			<p><a href="#services">IT Solutions</a></p>
		</div>
		<div class="footer-section">
			<h3>Community</h3>
			<p><a href="/maps">Discover Kosovo</a></p>
			<p><a href="/register">Join Community</a></p>
			<p><a href="/login">Member Login</a></p>
		</div>
		<div class="footer-section">
			<h3>Contact</h3>
			<p>✉ info@nggconsulting.com</p>
			<p>☎ +383 44 123 456</p>
			<p>⌖ Pristina, Kosovo</p>
			<p>◉ 6 Countries in Western Balkans</p>
		</div>
	</div>
	<div class="footer-bottom">
		<p>&copy; 2024 NGG Consulting. All rights reserved. | Empowering businesses, enriching communities.</p>
	</div>
</div>
{{end}}

{{define "register"}}
<div class="container">
	<div class="form-card">
		<h1>Join NGG Community</h1>
		<p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
			Get access to exclusive business resources and Kosovo's community platform
		</p>
		{{if .Error}}
			<div class="alert-error">{{.Error}}</div>
		{{end}}
		<form action="/register" method="POST">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="username" required placeholder="Choose your username">
			</div>
			<div class="form-group">
				<label for="email">Email Address</label>
				<input type="email" id="email" name="email" required placeholder="your@email.com">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required placeholder="Create a strong password">
			</div>
			<button type="submit" class="btn">Create Account</button>
		</form>
		<p style="text-align: center; margin-top: 2rem; color: var(--text-gray);">
			Already have an account? <a href="/login" style="color: #667eea;">Sign in here</a>
		</p>
	</div>
</div>
{{end}}

{{define "login"}}
<div class="container">
	<div class="form-card">
		<h1>Welcome Back</h1>
		<p style="text-align: center; color: var(--text-gray); margin-bottom: 2rem;">
			Sign in to access your dashboard and community features
		</p>
		{{if .Error}}
			<div class="alert-error">{{.Error}}</div>
		{{end}}
		<form action="/login" method="POST">
			<div class="form-group">
				<label for="email">Email Address</label>
				<input type="email" id="email" name="email" required placeholder="your@email.com">
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required placeholder="Enter your password">
			</div>
			<button type="submit" class="btn">Sign In</button>
		</form>
		<p style="text-align: center; margin-top: 2rem; color: var(--text-gray);">
			Don't have an account? <a href="/register" style="color: #667eea;">Register here</a>
		</p>
	</div>
</div>
{{end}}

{{define "dashboard"}}
<div class="container">
	<div class="dashboard-card">
		<h1>Welcome to Your Dashboard</h1>
		<p style="color: var(--text-gray); margin-bottom: 2rem;">
			Hello <strong style="color: var(--text-light);">{{.CurrentUser.Username}}</strong>! Manage your account and explore community features.
		</p>
		
		<div class="user-info">
			<h3 style="margin-bottom: 1.5rem; color: var(--text-light);">Account Information</h3>
			<ul>
				<li>
					<strong>User ID</strong>
					<span>{{.CurrentUser.ID}}</span>
				</li>
				<li>
					<strong>Username</strong>
					<span>{{.CurrentUser.Username}}</span>
				</li>
				<li>
					<strong>Email</strong>
					<span>{{.CurrentUser.Email}}</span>
				</li>
				<li>
					<strong>Account Status</strong>
					<span>{{if .CurrentUser.IsVerified}}✓ Verified{{else}}○ Pending Verification{{end}}</span>
				</li>
				<li>
					<strong>Account Type</strong>
					<span>{{if .CurrentUser.IsAdmin}}◆ Administrator{{else}}◦ Member{{end}}</span>
				</li>
			</ul>
		</div>
		
		<div style="margin-top: 3rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
			<a href="/maps" class="btn-primary" style="text-align: center;">Explore Kosovo Places</a>
			<a href="/" class="btn-secondary" style="text-align: center;">View Services</a>
		</div>
	</div>
</div>
{{end}}

{{define "admin"}}
<div class="container">
	<div class="dashboard-card">
		<h1>Admin Control Panel</h1>
		<p style="color: var(--text-gray); margin-bottom: 2rem;">
			Welcome, <strong style="color: var(--text-light);">{{.CurrentUser.Username}}</strong>. Manage all users and system settings from this panel.
		</p>
		
		{{if .Error}}
			<div class="alert-error">{{.Error}}</div>
		{{end}}
		{{if .Message}}
			<div class="alert-success">{{.Message}}</div>
		{{end}}
		
		<h2 style="margin-top: 3rem; margin-bottom: 1.5rem; color: var(--text-light);">User Management</h2>
		
		<div class="admin-table">
			<table>
				<thead>
					<tr>
						<th>ID</th>
						<th>Username</th>
						<th>Email</th>
						<th>Verified</th>
						<th>Role</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{{range .Users}}
					<tr>
						<td>{{.ID}}</td>
						<td>{{.Username}}</td>
						<td>{{.Email}}</td>
						<td>{{if .IsVerified}}✓{{else}}○{{end}}</td>
						<td>{{if .IsAdmin}}◆ Admin{{else}}◦ User{{end}}</td>
						<td>
							{{if eq .ID $.CurrentUser.ID}}
								<span style="color: var(--text-gray);">Current User</span>
							{{else}}
								{{if .IsAdmin}}
								<form action="/admin" method="POST" class="action-form">
									<input type="hidden" name="user_id" value="{{.ID}}">
									<input type="hidden" name="action" value="remove_admin">
									<button type="submit" class="btn-admin">Remove Admin</button>
								</form>
								{{else}}
								<form action="/admin" method="POST" class="action-form">
									<input type="hidden" name="user_id" value="{{.ID}}">
									<input type="hidden" name="action" value="make_admin">
									<button type="submit" class="btn-admin">Make Admin</button>
								</form>
								{{end}}
								<form action="/admin" method="POST" class="action-form" onsubmit="return confirm('Are you sure you want to delete this user?');">
									<input type="hidden" name="user_id" value="{{.ID}}">
									<input type="hidden" name="action" value="delete_user">
									<button type="submit" class="btn-delete">Delete User</button>
								</form>
							{{end}}
						</td>
					</tr>
					{{end}}
				</tbody>
			</table>
		</div>
	</div>
</div>
{{end}}

{{define "message"}}
<div class="container">
	<div class="form-card" style="text-align: center;">
		<h1>{{.Title}}</h1>
		<p style="font-size: 1.2rem; color: var(--text-gray); margin: 2rem 0;">{{.Message}}</p>
		<a href="/login" class="btn" style="display: inline-block; margin-top: 1rem;">Go to Login</a>
	</div>
</div>
{{end}}

{{define "maps"}}
<div class="container">
	<div class="community">
		<h2>Discover Kosovo Together</h2>
		<p style="text-align: center; color: var(--text-gray); margin-bottom: 3rem; font-size: 1.2rem;">
			Explore community-recommended places, share your favorite spots, and connect with fellow travelers
		</p>
		
		<div class="services-grid" style="margin-bottom: 3rem;">
			<div class="service-card" style="text-align: center;">
				<div class="service-icon">⌖</div>
				<h3>Share Places</h3>
				<p>Add your favorite locations and hidden gems for others to discover</p>
			</div>
			<div class="service-card" style="text-align: center;">
				<div class="service-icon">◎</div>
				<h3>Leave Reviews</h3>
				<p>Share your experiences and read authentic reviews from the community</p>
			</div>
			<div class="service-card" style="text-align: center;">
				<div class="service-icon">★</div>
				<h3>Get Recommendations</h3>
				<p>Find the best places recommended by locals and experienced travelers</p>
			</div>
		</div>
		
		<div class="map-container">
			<div class="map-header">
				<h3>◉ Interactive Community Map</h3>
				{{if .CurrentUser.ID}}
					<button class="btn-primary" style="padding: 0.8rem 2rem;">Add New Place</button>
				{{else}}
					<a href="/register" class="btn-primary" style="padding: 0.8rem 2rem;">Join to Add Places</a>
				{{end}}
			</div>
			<iframe class="map-iframe" src="https://www.google.com/maps/d/embed?mid=15kGHj7YZlrJZJgSFsfOPvS6ucMbH_RU&ehbc=2E312F" allowfullscreen="" loading="lazy"></iframe>
		</div>
		
		<div style="margin-top: 3rem; padding: 2rem; background: rgba(255, 255, 255, 0.05); border-radius: 15px;">
			<h3 style="color: var(--text-light); margin-bottom: 1rem;">Featured Places This Week</h3>
			<div class="services-grid">
				<div style="background: url('https://images.unsplash.com/photo-1609764196664-cdaee6a5a5d6?w=400&auto=format&fit=crop') center/cover; height: 200px; border-radius: 10px; position: relative;">
					<div style="position: absolute; bottom: 0; left: 0; right: 0; padding: 1rem; background: linear-gradient(to top, rgba(0,0,0,0.8), transparent); border-radius: 0 0 10px 10px;">
						<h4 style="color: white;">Rugova Mountains</h4>
						<p style="color: var(--text-gray); font-size: 0.9rem;">Pristine nature & hiking trails</p>
					</div>
				</div>
				<div style="background: url('https://images.unsplash.com/photo-1566994449469-3e17d43e7146?w=400&auto=format&fit=crop') center/cover; height: 200px; border-radius: 10px; position: relative;">
					<div style="position: absolute; bottom: 0; left: 0; right: 0; padding: 1rem; background: linear-gradient(to top, rgba(0,0,0,0.8), transparent); border-radius: 0 0 10px 10px;">
						<h4 style="color: white;">Prizren Castle</h4>
						<p style="color: var(--text-gray); font-size: 0.9rem;">Historic fortress with stunning views</p>
					</div>
				</div>
				<div style="background: url('https://images.unsplash.com/photo-1599757106551-65c23ac08677?w=400&auto=format&fit=crop') center/cover; height: 200px; border-radius: 10px; position: relative;">
					<div style="position: absolute; bottom: 0; left: 0; right: 0; padding: 1rem; background: linear-gradient(to top, rgba(0,0,0,0.8), transparent); border-radius: 0 0 10px 10px;">
						<h4 style="color: white;">Gadime Cave</h4>
						<p style="color: var(--text-gray); font-size: 0.9rem;">Natural marble cave system</p>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
{{end}}
`