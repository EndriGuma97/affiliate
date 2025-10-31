# Chapter 6: HTTP Routing and Handlers 🌐

## Welcome to Web Programming!

This is where your Go code becomes a web server! You'll learn how URLs become actions, how to handle form submissions, and how to send responses back to users.

---

## 📍 The Big Picture

**What is HTTP?**
HTTP (HyperText Transfer Protocol) is how web browsers and servers talk to each other.

**Simple analogy:**
```
Browser: "Hey server, give me the home page!"  (HTTP Request)
   ↓
Server: "Here you go: <html>...</html>"  (HTTP Response)
```

**Your app is an HTTP server that:**
1. Listens for requests on port 443 (HTTPS)
2. Routes URLs to handler functions
3. Processes the request (database queries, etc.)
4. Sends back HTML pages or JSON data

---

## 🗺️ Route Setup (Lines 237-268)

### The setupRoutes Function

```go
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
```

**🤔 What's a ServeMux?**

`ServeMux` is a **route multiplexer** - it matches URLs to handler functions.

```
User visits: https://yoursite.com/dashboard
              ↓
ServeMux looks at path: "/dashboard"
              ↓
Finds: mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
              ↓
Calls: requireAuth middleware → dashboardHandler
```

**Called from main (Lines 216-221):**
```go
mux := http.NewServeMux()
setupRoutes(mux)

log.Println("Starting HTTPS server on " + baseURL + " ...")
if err := http.ListenAndServeTLS(":443", certFile, keyFile, mux); err != nil {
	log.Fatal("Failed to start server:", err)
}
```

---

## 🎯 Understanding HTTP Requests and Responses

### The Request-Response Cycle

```
1. User clicks link or submits form
   ↓
2. Browser sends HTTP Request
   GET /dashboard HTTP/1.1
   Host: yoursite.com
   Cookie: session=abc123...
   ↓
3. Your Go server receives it
   ↓
4. ServeMux routes to handler
   ↓
5. Handler processes (query database, etc.)
   ↓
6. Handler sends HTTP Response
   HTTP/1.1 200 OK
   Content-Type: text/html
   <html>...</html>
   ↓
7. Browser displays the page
```

### HTTP Methods

| Method | Purpose | Example |
|--------|---------|---------|
| `GET` | Get/view data | Visit a page, load data |
| `POST` | Submit/create data | Submit form, create user |
| `PUT` | Update data | Edit profile |
| `DELETE` | Delete data | Remove account |

**Your app uses GET and POST:**

```go
if r.Method == http.MethodGet {
	// Show the form
	renderTemplate(w, "register", PageBundle{})
	return
}

// If not GET, handle POST
username := r.FormValue("username")
// Process registration...
```

---

## 🔓 Middleware Functions

Middleware wraps handlers to add functionality (like checking if user is logged in).

### 1. requireAuth Middleware (Lines 370-390)

```go
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
```

**🤔 How middleware works:**

```
User visits /dashboard
   ↓
requireAuth checks:
   1. Is user logged in? (session cookie)
   2. Is email verified?
   ↓
If YES: Call dashboardHandler with user in context
If NO: Redirect to /login
```

**Visual flow:**
```
Request
  ↓
┌─────────────────┐
│  requireAuth    │ ← Middleware
│  (check login)  │
└────────┬────────┘
         ↓
    Logged in?
    /        \
  YES         NO
   ↓           ↓
Handler    Redirect to /login
```

**Usage:**
```go
mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
//                           ↑ Wraps handler with auth check
```

### 2. requireAdmin Middleware (Lines 392-403)

```go
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
```

**Double protection:**
1. Must be logged in
2. Must be admin

**Usage:**
```go
mux.HandleFunc("/admin/", requireAdmin(adminHandler))
//                        ↑ Only admins can access
```

---

## 🏠 PUBLIC ROUTES (No login required)

### 1. homeHandler (Lines 405-411)

```go
func homeHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "home", PageBundle{
		PageName:    "home",
		CurrentUser: user,
	})
}
```

**Simple!**
- Gets current user (if logged in)
- Renders home page template
- Shows different content if logged in vs logged out

---

### 2. registerHandler (Lines 413-472)

```go
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Show registration form
		user, _ := getCurrentUser(r)
		renderTemplate(w, "register", PageBundle{
			CurrentUser: user,
		})
		return
	}

	// Handle POST - form submission
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Show error
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

	// Show success message
	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Registration Successful",
			Message: "Please check your email to verify your account.",
		},
	})
}
```

**🤔 GET vs POST pattern:**

All form handlers follow this pattern:

```go
if r.Method == http.MethodGet {
	// Show empty form
	return
}

// Handle POST (form submission)
// Process data...
// Save to database...
// Show result...
```

**Registration flow:**
```
1. User visits /register (GET)
   → Show registration form

2. User fills form and clicks Submit
   → Browser sends POST with form data

3. Handler processes:
   - Hash password with bcrypt
   - Generate verification token
   - Save user to database
   - Send verification email

4. Show success message
```

---

### 3. loginHandler (Lines 474-509)

```go
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
```

**🤔 Key security practices:**

1. **Password verification:**
```go
bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
```
Never compares plain passwords! Always hashes and compares.

2. **Generic error messages:**
```go
"Invalid username or password."
```
Doesn't reveal whether username exists (prevents user enumeration).

3. **Session creation:**
```go
session.Values["user_id"] = user.ID
session.Save(r, w)
```
Server creates encrypted cookie, sends to browser.

---

### 4. logoutHandler (Lines 511-516)

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

**Simple but important:**
1. Get session
2. Delete user_id from it
3. Save (updates cookie)
4. Redirect to home

**Result:** User is logged out!

---

### 5. verifyHandler (Lines 518-561)

```go
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
		// Database error
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
		// No user found with this token, or token expired
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid or Expired Token",
				Message: "The verification link is invalid or has expired.",
			},
		})
		return
	}

	// Success!
	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Email Verified",
			Message: "Your email has been successfully verified. You can now log in.",
		},
	})
}
```

**🤔 How email verification works:**

```
1. User registers
   → Gets token: "a7f3b82c..."
   → Stored in database with expiry

2. Email sent with link:
   https://yoursite.com/verify?token=a7f3b82c...

3. User clicks link
   → Browser visits /verify?token=a7f3b82c...

4. Handler checks:
   - Token exists in database?
   - Token not expired?

5. If valid:
   - Set is_verified = TRUE
   - Clear token (NULL)

6. User can now log in!
```

**🤔 What's `r.URL.Query().Get("token")`?**

Gets value from URL query string:
```
URL: /verify?token=abc123&other=value
     r.URL.Query().Get("token")  → "abc123"
     r.URL.Query().Get("other")  → "value"
```

---

### 6. forgotPasswordHandler (Lines 563-624)

```go
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
```

**🚨 Security note:**
```go
// Don't reveal if email exists or not for security
```

Always shows same message whether email exists or not. This prevents attackers from discovering which emails are registered.

---

### 7. resetPasswordHandler (Lines 626-717)

**Handles both showing the reset form (GET) and processing it (POST).**

**GET request:**
```go
// Verify token exists and is valid
var count int
err := db.QueryRow(
	"SELECT COUNT(*) FROM users WHERE password_reset_token = ? AND reset_token_expiry > ?",
	token, time.Now(),
).Scan(&count)

if err != nil || count == 0 {
	// Invalid or expired token
	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Invalid Reset Link",
			Message: "This password reset link is invalid or has expired.",
		},
	})
	return
}

// Show reset form
renderTemplate(w, "reset_password", PageBundle{
	Data: map[string]string{
		"token": token,
	},
})
```

**POST request:**
```go
newPassword := r.FormValue("password")
confirmPassword := r.FormValue("confirm_password")

if newPassword != confirmPassword {
	// Passwords don't match
	return
}

// Hash new password
hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

// Update password and clear reset token
result, err := db.Exec(
	`UPDATE users
	 SET password_hash = ?, password_reset_token = NULL, reset_token_expiry = NULL
	 WHERE password_reset_token = ? AND reset_token_expiry > ?`,
	string(hashedPassword), token, time.Now(),
)
```

**Password reset flow:**
```
1. User forgets password
2. Visits /forgot-password
3. Enters email
4. Gets email with reset link
5. Clicks link → /reset-password?token=xyz
6. Shows reset form
7. Enters new password
8. Password updated, token cleared
9. Can log in with new password!
```

---

## 🔒 PROTECTED ROUTES (Login required)

These handlers use `requireAuth` middleware.

### 8. dashboardHandler (Lines 719-728)

```go
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
```

**🤔 How does it get the user?**

```go
user := r.Context().Value("user").(User)
```

The `requireAuth` middleware put it there:
```go
ctx := context.WithValue(r.Context(), "user", user)
next(w, r.WithContext(ctx))
```

**Context is like a backpack that travels with the request!**

---

### 9. changePasswordHandler (Lines 730-808)

**GET: Show change password form**
**POST: Process password change**

```go
// Verify current password
var storedHash string
err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&storedHash)
if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)) != nil {
	// Current password is wrong
	return
}

// Verify new passwords match
if newPassword != confirmPassword {
	// Passwords don't match
	return
}

// Hash new password
hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

// Update password
_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashedPassword), user.ID)
```

**Security checks:**
1. ✅ Verify current password (can't change if you don't know it)
2. ✅ Confirm new password (prevent typos)
3. ✅ Hash with bcrypt (never store plain passwords)

---

### 10. deleteAccountHandler (Lines 810-885)

**Permanently deletes user account and all their data.**

```go
// Verify password
var storedHash string
err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&storedHash)
if err != nil || bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) != nil {
	// Password is incorrect
	return
}

// Verify confirmation text
if confirmation != "DELETE" {
	// Must type DELETE to confirm
	return
}

// Delete user's comments
db.Exec("DELETE FROM comments WHERE user_id = ?", user.ID)

// Delete user's places
db.Exec("DELETE FROM places WHERE submitted_by_user_id = ?", user.ID)

// Delete user account
_, err = db.Exec("DELETE FROM users WHERE id = ?", user.ID)

// Clear session
session, _ := store.Get(r, "session")
delete(session.Values, "user_id")
session.Save(r, w)
```

**🚨 Danger zone!** Requires:
1. Password verification
2. Typing "DELETE" to confirm
3. Deletes all user data (comments, places, account)
4. Logs user out

**Deletion order matters:**
```
1. Delete comments (foreign key)
2. Delete places (foreign key)
3. Delete user (main record)
```

---

## 👑 ADMIN ROUTES (Admin-only)

### 11. adminHandler (Lines 887-964)

**Admin user management panel.**

```go
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
		session.Save(r, w)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	// Get all users
	rows, err := db.Query("SELECT id, username, email, is_verified, is_admin FROM users ORDER BY id")
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
		users = append(users, u)
	}

	// Count pending places
	var pendingCount int
	db.QueryRow("SELECT COUNT(*) FROM places WHERE is_approved = FALSE").Scan(&pendingCount)

	// Render admin page
	renderTemplate(w, "admin", PageBundle{
		PageName: "admin",
		Data: AdminPageData{
			CurrentUser:  user,
			Users:        users,
			PendingCount: pendingCount,
		},
	})
}
```

**Actions admin can do:**
- Toggle admin status for users
- Delete users
- View all users
- See count of pending places

---

### 12. adminPlacesHandler (Lines 966-1080)

**Admin place approval/rejection panel.**

```go
if r.Method == http.MethodPost {
	placeID, _ := strconv.Atoi(r.FormValue("place_id"))
	action := r.FormValue("action")

	switch action {
	case "approve":
		// Get coordinates from form
		lat, _ := strconv.ParseFloat(r.FormValue("latitude"), 64)
		lng, _ := strconv.ParseFloat(r.FormValue("longitude"), 64)

		_, err := db.Exec("UPDATE places SET is_approved = TRUE, latitude = ?, longitude = ? WHERE id = ?",
			lat, lng, placeID)

	case "delete":
		// Delete comments first
		_, err := db.Exec("DELETE FROM comments WHERE place_id = ?", placeID)
		// Then delete place
		_, err = db.Exec("DELETE FROM places WHERE id = ?", placeID)
	}
}

// Get ALL places (pending and approved)
rows, err := db.Query(`
	SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
	       p.google_maps_link, p.created_at, p.is_approved, u.username,
	       (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
	FROM places p
	JOIN users u ON p.submitted_by_user_id = u.id
	ORDER BY p.is_approved ASC, p.created_at DESC
`)
```

**Admin can:**
- Approve places (and set coordinates)
- Delete places
- View both pending and approved places

---

## 🗺️ PLACES ROUTES

### 13. mapHandler (Lines 1082-1088)

```go
func mapHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "map", PageBundle{
		PageName:    "map",
		CurrentUser: user,
	})
}
```

**Simple:** Just renders the interactive map page.
JavaScript on the page then calls `/api/places` to load markers.

---

### 14. placesHandler (Lines 1090-1162)

**Browse places with search and category filters.**

```go
func placesHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)

	searchQuery := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")

	// Build query dynamically
	query := "SELECT * FROM places WHERE is_approved = TRUE"
	args := []interface{}{}

	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}

	if searchQuery != "" {
		query += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)"
		searchParam := "%" + strings.ToLower(searchQuery) + "%"
		args = append(args, searchParam, searchParam)
	}

	query += " ORDER BY created_at DESC LIMIT 50"

	// Execute query
	rows, err := db.Query(query, args...)

	var places []Place
	for rows.Next() {
		var p Place
		rows.Scan(&p.ID, &p.Title, ...)
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
```

**URL examples:**
```
/places                           ← All places
/places?category=Historical        ← Filtered by category
/places?search=castle              ← Search query
/places?category=Historical&search=castle  ← Both filters
```

---

### 15. placeDetailHandler (Lines 1164-1230)

**Show single place with all details and comments.**

```go
func placeDetailHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)

	// Extract place ID from URL
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Invalid place ID", http.StatusBadRequest)
		return
	}
	placeID, err := strconv.Atoi(pathParts[2])

	// Get place details
	var place Place
	err = db.QueryRow(`
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
		       p.google_maps_link, p.created_at, u.username
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		WHERE p.id = ? AND p.is_approved = TRUE
	`, placeID).Scan(&place.ID, &place.Title, ...)

	if err != nil {
		// Place not found
		http.Error(w, "Place not found", http.StatusNotFound)
		return
	}

	// Get all comments for this place
	rows, err := db.Query(`
		SELECT c.id, c.place_id, c.user_id, u.username, c.content,
		       c.image_url, c.created_at
		FROM comments c
		JOIN users u ON c.user_id = u.id
		WHERE c.place_id = ?
		ORDER BY c.created_at DESC
	`, placeID)

	var comments []Comment
	for rows.Next() {
		var c Comment
		rows.Scan(&c.ID, &c.PlaceID, &c.UserID, &c.Username, &c.Content, &c.ImageURL, &c.CreatedAt)
		comments = append(comments, c)
	}

	// Render place detail page
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
```

**🤔 URL parsing:**
```
URL: /place/42
     Split by "/": ["", "place", "42"]
     pathParts[2] = "42"
     Convert to int: 42
```

---

## 💬 CHAT & COUNSELING ROUTES

### 16. chatPageHandler (Lines 1308-1317)

```go
func chatPageHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "chat", PageBundle{
		PageName: "chat",
		Data: ChatPageData{
			Greeting: "Hello! How can I help you explore Kosovo today?",
		},
		CurrentUser: user,
	})
}
```

**Shows the AI chatbot interface.**
JavaScript on the page then calls `/api/chat` to process messages.

---

### 17. counselingHandler (Lines 1319-1325)

```go
func counselingHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	renderTemplate(w, "counseling", PageBundle{
		PageName:    "counseling",
		CurrentUser: user,
	})
}
```

**Shows counseling/consultation booking page.**

---

### 18. counselingSubmitHandler (Lines 1327-1408)

**Processes counseling appointment requests.**

```go
func counselingSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get form data
	name := r.FormValue("name")
	email := r.FormValue("email")
	phone := r.FormValue("phone")
	message := r.FormValue("message")
	preferredDate := r.FormValue("preferred_date")
	preferredTime := r.FormValue("preferred_time")

	// Build email body
	emailBody := fmt.Sprintf(`
New Counseling Request:

Name: %s
Email: %s
Phone: %s
Preferred Date: %s
Preferred Time: %s

Message:
%s
	`, name, email, phone, preferredDate, preferredTime, message)

	// Send notification email to counselor
	err := sendEmail("endrig@needgreatersglobal.com", "New Counseling Request", emailBody)
	if err != nil {
		log.Printf("Failed to send counseling email: %v", err)
		// Still show success to user
	}

	// Send confirmation to user
	confirmationBody := fmt.Sprintf(`
Hello %s,

Thank you for your interest in our counseling services. We have received your request for %s at %s.

We will contact you within 24 hours to confirm your appointment.

Best regards,
Kosovo Explorer Team
	`, name, preferredDate, preferredTime)

	sendEmail(email, "Counseling Request Received", confirmationBody)

	// Show success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Your request has been submitted. We'll contact you soon!",
	})
}
```

**Flow:**
1. User fills counseling form
2. Handler sends email to counselor
3. Handler sends confirmation to user
4. Returns JSON success response

---

## 🔌 API ROUTES (JSON responses)

### 19. chatAPIHandler (Lines 1410-1474)

**AI chat endpoint - classifies user intent using Gemini AI.**

```go
func chatAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON request
	var req AIChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Call Gemini AI to classify intent
	classification, err := classifyUserPrompt(req.Prompt)
	if err != nil {
		log.Printf("AI classification error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AIChatResponse{
			Type: "other",
		})
		return
	}

	// Build response based on classification
	var response AIChatResponse

	switch classification {
	case "counseling":
		response = AIChatResponse{
			Type: "counseling",
		}
	case "places":
		// Extract keywords and category from prompt
		keyword, category := extractSearchTerms(req.Prompt)
		response = AIChatResponse{
			Type: "places",
			Content: map[string]string{
				"keyword":  keyword,
				"category": category,
			},
		}
	default:
		response = AIChatResponse{
			Type: "other",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
```

**Example flow:**
```
JavaScript sends: {"prompt": "I want to see castles"}
   ↓
classifyUserPrompt() calls Gemini AI
   ↓
Gemini returns: "places"
   ↓
extractSearchTerms() finds: keyword="castle", category=""
   ↓
Handler returns JSON: {
  "type": "places",
  "content": {"keyword": "castle", "category": ""}
}
   ↓
JavaScript redirects to: /places?search=castle
```

---

### 20. placesAPIHandler (Lines 1476-1574)

**API to get places as JSON (for map markers, AJAX loading).**

```go
func placesAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	searchQuery := r.URL.Query().Get("search")
	category := r.URL.Query().Get("category")

	// Build dynamic query
	query := `
		SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
		       p.google_maps_link, p.created_at, p.is_approved, u.username,
		       (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
		FROM places p
		JOIN users u ON p.submitted_by_user_id = u.id
		WHERE p.is_approved = TRUE
	`
	args := []interface{}{}

	if category != "" {
		query += " AND p.category = ?"
		args = append(args, category)
	}

	if searchQuery != "" {
		query += " AND (LOWER(p.title) LIKE ? OR LOWER(p.description) LIKE ?)"
		searchParam := "%" + strings.ToLower(searchQuery) + "%"
		args = append(args, searchParam, searchParam)
	}

	query += " ORDER BY p.created_at DESC"

	// Execute query
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var places []Place
	for rows.Next() {
		var p Place
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category,
		          &p.Latitude, &p.Longitude, &p.GoogleMapsLink,
		          &p.CreatedAt, &p.IsApproved, &p.SubmittedByUsername,
		          &p.CommentCount)
		places = append(places, p)
	}

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(places)
}
```

**JavaScript usage:**
```javascript
// Load places for map
fetch('/api/places')
  .then(res => res.json())
  .then(places => {
    places.forEach(place => {
      // Add marker to map
      addMarker(place.Latitude, place.Longitude, place.Title);
    });
  });

// Load filtered places
fetch('/api/places?category=Historical&search=castle')
  .then(res => res.json())
  .then(places => {
    // Display results
  });
```

---

### 21. submitPlaceHandler (Lines 1232-1275)

**Submit a new place (JSON API).**

```go
func submitPlaceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current user
	user, err := getCurrentUser(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"message": "You must be logged in to submit places",
		})
		return
	}

	// Get form data
	title := r.FormValue("title")
	description := r.FormValue("description")
	category := r.FormValue("category")
	googleMapsLink := r.FormValue("google_maps_link")

	// Insert into database (not approved by default)
	_, err = db.Exec(`
		INSERT INTO places (title, description, category, google_maps_link, submitted_by_user_id)
		VALUES (?, ?, ?, ?, ?)`,
		title, description, category, googleMapsLink, user.ID,
	)

	if err != nil {
		log.Printf("Error inserting place: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"message": "Failed to submit place",
		})
		return
	}

	// Success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"message": "Place submitted for review",
	})
}
```

**Flow:**
1. Check user is logged in
2. Get form data
3. Insert into database (is_approved = FALSE)
4. Return JSON response
5. Admin must approve before it's visible

---

### 22. commentHandler (Lines 1277-1306)

**Add a comment to a place (protected API).**

```go
func commentHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get form data
	placeIDStr := r.FormValue("place_id")
	content := r.FormValue("content")
	imageURL := r.FormValue("image_url")

	placeID, err := strconv.Atoi(placeIDStr)
	if err != nil {
		http.Error(w, "Invalid place ID", http.StatusBadRequest)
		return
	}

	// Insert comment
	_, err = db.Exec(`
		INSERT INTO comments (place_id, user_id, content, image_url)
		VALUES (?, ?, ?, ?)`,
		placeID, user.ID, content, imageURL,
	)

	if err != nil {
		http.Error(w, "Failed to add comment", http.StatusInternalServerError)
		return
	}

	// Redirect back to place detail page
	http.Redirect(w, r, fmt.Sprintf("/place/%d", placeID), http.StatusSeeOther)
}
```

**Protected with `requireAuth`:**
```go
mux.HandleFunc("/api/comment", requireAuth(commentHandler))
```

Must be logged in to comment!

---

## 📊 Summary of All Routes

| Route | Method | Access | Handler | Purpose |
|-------|--------|--------|---------|---------|
| `/` | GET | Public | homeHandler | Home page |
| `/register` | GET/POST | Public | registerHandler | User registration |
| `/login` | GET/POST | Public | loginHandler | User login |
| `/logout` | GET | Public | logoutHandler | User logout |
| `/verify` | GET | Public | verifyHandler | Email verification |
| `/forgot-password` | GET/POST | Public | forgotPasswordHandler | Request password reset |
| `/reset-password` | GET/POST | Public | resetPasswordHandler | Reset password |
| `/map` | GET | Public | mapHandler | Interactive map |
| `/places` | GET | Public | placesHandler | Browse places |
| `/place/{id}` | GET | Public | placeDetailHandler | Place details |
| `/chat` | GET | Public | chatPageHandler | AI chatbot |
| `/counseling` | GET | Public | counselingHandler | Counseling booking |
| `/dashboard` | GET | Protected | dashboardHandler | User dashboard |
| `/change-password` | GET/POST | Protected | changePasswordHandler | Change password |
| `/delete-account` | GET/POST | Protected | deleteAccountHandler | Delete account |
| `/admin/` | GET/POST | Admin | adminHandler | User management |
| `/admin/places` | GET/POST | Admin | adminPlacesHandler | Place approval |
| `/api/chat` | POST | Public | chatAPIHandler | AI chat API |
| `/api/places` | GET | Public | placesAPIHandler | Get places JSON |
| `/api/places/submit` | POST | Public | submitPlaceHandler | Submit new place |
| `/api/comment` | POST | Protected | commentHandler | Add comment |
| `/api/counseling/submit` | POST | Public | counselingSubmitHandler | Submit counseling request |

---

## 💡 Key Takeaways

✅ **ServeMux routes URLs to handlers** - Like a switchboard
✅ **Middleware wraps handlers** - Adds functionality (auth, logging, etc.)
✅ **GET shows forms, POST processes them** - Standard pattern
✅ **Context carries data between middleware and handlers** - Like a backpack
✅ **Always check r.Method** - Different logic for GET vs POST
✅ **Return JSON for APIs** - `json.NewEncoder(w).Encode(data)`
✅ **Redirect after POST** - Prevents form resubmission
✅ **Extract URL params** - `r.URL.Query().Get("param")` or parse path
✅ **Session cookies keep users logged in** - Server-side encrypted storage

---

## 🚀 Next Steps

Now you understand how web requests flow through your app! Next, let's dive deep into authentication and security.

**Next chapter:** [Authentication and Sessions](07-authentication-sessions.md)
Learn how login, sessions, password hashing, and security work!

---

**Remember:** HTTP handlers are where your app comes to life - they connect users to your code! 🌐

---

*Happy coding! Next up: Security and authentication* 🌐➡️🔐
