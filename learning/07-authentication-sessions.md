# Chapter 7: Authentication and Sessions 🔐

## Welcome to Security!

Authentication is HOW your app knows who you are. Sessions are HOW it remembers you across page visits. This chapter covers the security foundation of your app!

---

## 📍 The Big Picture

**Authentication = Proving who you are**
- Username + Password
- Email verification
- Password reset

**Session = Remembering who you are**
- After login, server creates encrypted cookie
- Browser sends cookie with every request
- Server reads cookie to know you're still logged in

**Security = Keeping everything safe**
- bcrypt password hashing (uncrackable)
- Secure session cookies (encrypted)
- HTTPS-only communication (SSL/TLS)

---

## 🔑 Password Hashing with bcrypt

### Why We NEVER Store Plain Passwords

**❌ TERRIBLE - Plain text passwords:**
```
Database:
- alice: password123
- bob:   mydog2024
- carol: qwerty

Hacker steals database:
→ Game over! All passwords exposed!
→ Users who reuse passwords compromised everywhere!
```

**✅ GOOD - Hashed passwords:**
```
Database:
- alice: $2a$10$N9qo8uLOickgx2ZMRZoMyeIj...
- bob:   $2a$10$7hFn3XJ9mRkKNGf8g2jN4eOp...
- carol: $2a$10$M8no9kLPRqS5tGh4nH2jK9Ql...

Hacker steals database:
→ Can't reverse the hashes!
→ Would take millions of years to crack!
```

### How bcrypt Works

**Hashing (Registration) - Line 428:**
```go
hashedPassword, err := bcrypt.GenerateFromPassword(
	[]byte(password),
	bcrypt.DefaultCost,
)
// "password123" → "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
```

**What happens:**
```
1. Take password: "password123"
2. Generate random salt (makes each hash unique)
3. Run bcrypt algorithm (intentionally slow!)
4. Get hash: "$2a$10$N9qo..."
```

**Verification (Login) - Line 501:**
```go
err := bcrypt.CompareHashAndPassword(
	[]byte(user.PasswordHash),  // From database
	[]byte(password),            // User typed this
)

if err != nil {
	// Wrong password!
} else {
	// Correct password!
}
```

**What happens:**
```
1. User types password: "password123"
2. bcrypt hashes it with same salt
3. Compares hashes:
   - Database: $2a$10$N9qo8uLO...
   - Generated: $2a$10$N9qo8uLO...
   - Match? → Login successful!
```

### Anatomy of a bcrypt Hash

```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
 │   │  │                         │
 │   │  └─ Random salt ──────────────────────────────────────┘
 │   └──── Cost (difficulty) = 10
 └──────── Algorithm version = 2a
```

**Cost = how many rounds:**
```
Cost 10 = 2^10 = 1,024 rounds   (~100ms)
Cost 12 = 2^12 = 4,096 rounds   (~400ms)
Cost 14 = 2^14 = 16,384 rounds  (~1.6 seconds)
```

**Why slow is good:**
- For normal login: 100ms is fine (user doesn't notice)
- For attacker: Trying 1 million passwords = 1,000,000 × 100ms = 27 hours per million!

**bcrypt.DefaultCost = 10** (good balance)

### bcrypt Security Features

**1. Salted automatically:**
```go
bcrypt.GenerateFromPassword([]byte("password123"), 10)
// First time:  $2a$10$abc...
// Second time: $2a$10$xyz...  ← Different hash! Same password!
```

Each hash has unique salt = can't use rainbow tables!

**2. Adaptive difficulty:**
```go
// Today: Cost 10 is good
bcrypt.GenerateFromPassword(pwd, 10)

// Future: Computers faster? Just increase cost!
bcrypt.GenerateFromPassword(pwd, 12)  // Still works!
```

**3. Designed to be slow:**
- Fast algorithms (MD5, SHA1) = bad for passwords
- bcrypt intentionally slow = makes brute force impractical

---

## 🍪 Session Management with Gorilla Sessions

### What is a Session?

**Problem:** HTTP is **stateless** (each request is independent)

```
User logs in on Request 1
   ↓
Request 2: Server has no idea who you are!
Request 3: Still no idea!
Request 4: Still no idea!
```

**Solution:** Sessions!

```
User logs in
   ↓
Server creates session, sends encrypted cookie
   ↓
Browser stores cookie
   ↓
Every request includes cookie
   ↓
Server reads cookie: "Oh, this is user 42!"
```

### Session Setup (Lines 207-215)

```go
// Create session store
store = sessions.NewCookieStore([]byte(sessionKey))

// Configure security options
store.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   86400 * 7, // 7 days in seconds
	HttpOnly: true,      // Can't be accessed by JavaScript
	Secure:   true,      // Only send over HTTPS
}
```

**Options explained:**

| Option | Value | What it means |
|--------|-------|---------------|
| `Path` | `"/"` | Cookie valid for entire site |
| `MaxAge` | `86400 * 7` | Cookie expires after 7 days |
| `HttpOnly` | `true` | JavaScript can't access (prevents XSS theft) |
| `Secure` | `true` | Only sent over HTTPS (prevents interception) |

**🤔 What's the sessionKey?**

```go
const sessionKey = "a-very-secret-key-32-bytes-long"
```

Used to **encrypt** and **sign** cookies:
- Encryption: Cookie contents are unreadable
- Signing: Tampering is detectable

**🚨 Security note:** Keep this key secret! Anyone with the key can create fake sessions!

### Creating a Session (Login) - Lines 507-510

```go
// After successful password verification
session, _ := store.Get(r, "session")
session.Values["user_id"] = user.ID  // Store user ID
session.Save(r, w)  // Send cookie to browser
```

**What happens:**
```
1. Create/get session
2. Store user_id in it
3. Encrypt and sign the session data
4. Send as cookie:
   Set-Cookie: session=MTUwOTI3NzQ5N... HttpOnly; Secure
5. Browser stores it
```

**Cookie example:**
```
Name: session
Value: MTUwOTI3NzQ5NnxEdi1CQkFFQ180SUFBUkFCRUFBQU12LUNBQUVHYzNSeWFXNW5EQThBRFdGM...
Options: HttpOnly, Secure, Max-Age=604800
```

### Reading a Session - Lines 355-363

```go
func getCurrentUser(r *http.Request) (User, error) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["user_id"].(int)

	if !ok || userID == 0 {
		return User{}, fmt.Errorf("no valid session")
	}

	// Query database for user details
	var user User
	err := db.QueryRow(
		"SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)

	return user, err
}
```

**Flow:**
```
1. Browser sends cookie with request
2. store.Get() decrypts and verifies cookie
3. Extract user_id from session
4. Look up full user details in database
5. Return User struct
```

**Why not store everything in session?**
```go
// ❌ Bad - storing too much
session.Values["user_id"] = user.ID
session.Values["username"] = user.Username
session.Values["email"] = user.Email
session.Values["is_verified"] = user.IsVerified
session.Values["is_admin"] = user.IsAdmin
// Cookie becomes huge! And data can become stale.

// ✅ Good - only store ID
session.Values["user_id"] = user.ID
// Then query database for fresh data when needed
```

### Destroying a Session (Logout) - Lines 515-520

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")  // Remove user_id
	session.Save(r, w)  // Update cookie
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

**What happens:**
```
1. Get session
2. Delete user_id key
3. Save (sends updated cookie)
4. Browser now has empty session
5. getCurrentUser() will return error (no user_id)
6. User is logged out!
```

---

## ✉️ Email Verification Flow

### Why Email Verification?

**Prevents:**
- Fake accounts (spam bots)
- Typos in email address
- Someone registering with your email

**Ensures:**
- User owns the email address
- Can contact user if needed
- Better quality user base

### The Complete Flow

```
1. User registers
   ↓
2. Hash password, generate token
   ↓
3. Save user with is_verified = FALSE
   ↓
4. Send email with verification link
   ↓
5. User clicks link
   ↓
6. Verify token, set is_verified = TRUE
   ↓
7. User can now fully use the app
```

### Step 1: Generate Token (Lines 440-442)

```go
token := generateToken()
expiry := time.Now().Add(24 * time.Hour)  // Valid for 24 hours
```

**generateToken() function (Lines 1217-1221):**
```go
func generateToken() string {
	b := make([]byte, 32)  // 32 bytes = 256 bits
	rand.Read(b)  // Fill with cryptographically secure random data
	return hex.EncodeToString(b)  // Convert to hex string
}
```

**Example token:**
```
a7f3b82c4d9e1f6a8b2c5e7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a
```

**Why 32 bytes?**
- 2^256 possible values
- Impossible to guess even with billions of attempts

### Step 2: Store Token in Database (Lines 445-447)

```go
_, err = db.Exec(
	"INSERT INTO users (username, email, password_hash, verification_token, token_expiry) VALUES (?, ?, ?, ?, ?)",
	username, email, string(hashedPassword), token, expiry,
)
```

**Database row:**
```
id: 42
username: john_doe
email: john@example.com
password_hash: $2a$10$N9qo...
is_verified: FALSE  ← Not verified yet!
verification_token: a7f3b82c...
token_expiry: 2024-01-16 10:30:00
```

### Step 3: Send Verification Email (Lines 459-463)

```go
verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify your email: %s\n\nThis link expires in 24 hours.",
	username, verificationLink)

if err := sendEmail(email, "Verify Your Email", emailBody); err != nil {
	log.Printf("Failed to send verification email: %v", err)
}
```

**Email content:**
```
To: john@example.com
Subject: Verify Your Email

Welcome john_doe!

Click here to verify your email:
https://explorer.needgreatersglobal.com/verify?token=a7f3b82c...

This link expires in 24 hours.
```

### Step 4: User Clicks Link

```
Browser visits:
https://explorer.needgreatersglobal.com/verify?token=a7f3b82c...
   ↓
Routed to: verifyHandler
```

### Step 5: Verify Token (Lines 522-561)

```go
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token from URL
	token := r.URL.Query().Get("token")
	if token == "" {
		// No token provided
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid Token",
				Message: "Verification token is missing.",
			},
		})
		return
	}

	// Update user (if token valid and not expired)
	result, err := db.Exec(
		`UPDATE users
		 SET is_verified = TRUE, verification_token = NULL
		 WHERE verification_token = ? AND token_expiry > ?`,
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

	// Check if any rows were updated
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

**What this query does:**
```sql
UPDATE users
SET is_verified = TRUE, verification_token = NULL
WHERE verification_token = ? AND token_expiry > ?
```

**Conditions:**
1. Token matches database
2. Token not expired (`token_expiry > NOW()`)

**If both true:**
- Set `is_verified = TRUE`
- Clear token (`NULL`)
- Return success

**If either false:**
- No rows updated
- Return error

### Security Features

✅ **Token is random** - Can't be guessed
✅ **Token expires** - Can't be used after 24 hours
✅ **Token cleared after use** - Can't verify twice
✅ **Token in URL, not cookie** - Works even if not logged in

---

## 🔐 Password Reset Flow

**Similar to email verification, but for resetting forgotten passwords.**

### The Complete Flow

```
1. User forgot password, visits /forgot-password
   ↓
2. Enters email address
   ↓
3. Generate reset token, store in DB
   ↓
4. Send email with reset link
   ↓
5. User clicks link
   ↓
6. Show reset form
   ↓
7. User enters new password
   ↓
8. Update password, clear token
   ↓
9. User can log in with new password!
```

### Step 1: Request Reset (Lines 567-624)

```go
func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Show forgot password form
		return
	}

	// Handle POST
	email := r.FormValue("email")

	var userID int
	var username string
	err := db.QueryRow("SELECT id, username FROM users WHERE email = ?", email).Scan(&userID, &username)

	if err != nil {
		// 🚨 IMPORTANT: Don't reveal if email exists!
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Password Reset Email Sent",
				Message: "If an account exists with this email, a password reset link has been sent.",
			},
		})
		return
	}

	// Generate reset token (shorter expiry than email verification)
	token := generateToken()
	expiry := time.Now().Add(1 * time.Hour)  // 1 hour

	// Store token
	_, err = db.Exec(
		"UPDATE users SET password_reset_token = ?, reset_token_expiry = ? WHERE id = ?",
		token, expiry, userID,
	)

	// Send reset email
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)
	emailBody := fmt.Sprintf(`Hello %s,

You requested a password reset. Click the link below to reset your password:

%s

This link expires in 1 hour.

If you didn't request this, please ignore this email.`, username, resetLink)

	sendEmail(email, "Password Reset Request", emailBody)

	// Always show same message (security)
	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Password Reset Email Sent",
			Message: "If an account exists with this email, a password reset link has been sent.",
		},
	})
}
```

**🚨 Security principle: Information disclosure**

```go
// ❌ BAD - reveals if email exists
if err != nil {
	return "Email not found"
} else {
	return "Reset link sent to email"
}

// Attacker can discover which emails are registered!

// ✅ GOOD - same message always
"If an account exists with this email, a password reset link has been sent."

// Attacker can't tell if email exists or not
```

### Step 2: Verify Token and Show Form (Lines 630-663)

```go
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if r.Method == http.MethodGet {
		// Check if token is valid
		var count int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM users WHERE password_reset_token = ? AND reset_token_expiry > ?",
			token, time.Now(),
		).Scan(&count)

		if err != nil || count == 0 {
			// Token invalid or expired
			renderTemplate(w, "message", PageBundle{
				Data: MessagePageData{
					Title:   "Invalid Reset Link",
					Message: "This password reset link is invalid or has expired.",
				},
			})
			return
		}

		// Token valid, show reset form
		renderTemplate(w, "reset_password", PageBundle{
			Data: map[string]string{
				"token": token,  // Pass token to form
			},
		})
		return
	}

	// Handle POST (continue to step 3...)
}
```

**Form includes hidden token field:**
```html
<form method="POST" action="/reset-password">
	<input type="hidden" name="token" value="a7f3b82c...">
	<input type="password" name="password" placeholder="New Password">
	<input type="password" name="confirm_password" placeholder="Confirm Password">
	<button type="submit">Reset Password</button>
</form>
```

### Step 3: Process Reset (Lines 664-717)

```go
	// Handle POST
	newPassword := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Verify passwords match
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
		// Failed to hash
		return
	}

	// Update password and clear reset token
	result, err := db.Exec(
		`UPDATE users
		 SET password_hash = ?, password_reset_token = NULL, reset_token_expiry = NULL
		 WHERE password_reset_token = ? AND reset_token_expiry > ?`,
		string(hashedPassword), token, time.Now(),
	)

	if err != nil {
		// Database error
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Token invalid or expired
		renderTemplate(w, "message", PageBundle{
			Data: MessagePageData{
				Title:   "Invalid Reset Link",
				Message: "This password reset link is invalid or has expired.",
			},
		})
		return
	}

	// Success!
	renderTemplate(w, "message", PageBundle{
		Data: MessagePageData{
			Title:   "Password Reset Successful",
			Message: "Your password has been reset successfully. You can now log in with your new password.",
		},
	})
}
```

**SQL does everything atomically:**
```sql
UPDATE users
SET password_hash = ?, password_reset_token = NULL, reset_token_expiry = NULL
WHERE password_reset_token = ? AND reset_token_expiry > ?
```

**Conditions:**
1. Token matches
2. Token not expired

**If both true:**
- Update password
- Clear reset token
- Return success

**If either false:**
- No rows updated
- Token already used or expired

---

## 🛡️ Middleware Protection

### requireAuth Middleware (Lines 370-390)

**Purpose:** Ensure user is logged in and email verified

```go
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try to get current user
		user, err := getCurrentUser(r)
		if err != nil {
			// Not logged in
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check if email verified
		if !user.IsVerified {
			renderTemplate(w, "message", PageBundle{
				Data: MessagePageData{
					Title:   "Email Not Verified",
					Message: "Please verify your email address to access this page.",
				},
			})
			return
		}

		// User is logged in and verified!
		// Put user in context for handler to access
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}
```

**Visual flow:**
```
Request to /dashboard
   ↓
requireAuth middleware
   ↓
Is user logged in?
   ├─ NO → Redirect to /login
   └─ YES → Is email verified?
             ├─ NO → Show "verify email" message
             └─ YES → Call dashboardHandler
```

**Usage:**
```go
mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
mux.HandleFunc("/change-password", requireAuth(changePasswordHandler))
mux.HandleFunc("/delete-account", requireAuth(deleteAccountHandler))
mux.HandleFunc("/api/comment", requireAuth(commentHandler))
```

### requireAdmin Middleware (Lines 392-403)

**Purpose:** Ensure user is admin

```go
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := getCurrentUser(r)
		if err != nil || !user.IsAdmin {
			// Not logged in OR not admin
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// User is admin!
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}
```

**Double check:**
1. Must be logged in (getCurrentUser succeeds)
2. Must be admin (`user.IsAdmin == true`)

**Usage:**
```go
mux.HandleFunc("/admin/", requireAdmin(adminHandler))
mux.HandleFunc("/admin/places", requireAdmin(adminPlacesHandler))
```

---

## 🔒 Security Best Practices in Your Code

### 1. Password Security ✅

**✅ Using bcrypt:**
```go
bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

**✅ Never comparing plain passwords:**
```go
// ❌ NEVER do this!
if password == user.Password { ... }

// ✅ Always do this!
bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
```

### 2. Session Security ✅

**✅ HttpOnly cookies:**
```go
store.Options = &sessions.Options{
	HttpOnly: true,  // JavaScript can't access
}
```
Prevents XSS attacks from stealing session cookies.

**✅ Secure cookies:**
```go
store.Options = &sessions.Options{
	Secure: true,  // Only sent over HTTPS
}
```
Prevents man-in-the-middle attacks.

**✅ Encrypted session data:**
```go
store = sessions.NewCookieStore([]byte(sessionKey))
```
Cookie contents are encrypted, can't be read or tampered with.

### 3. SQL Injection Prevention ✅

**✅ Always using parameterized queries:**
```go
db.Exec("INSERT INTO users (username, email) VALUES (?, ?)", username, email)
//                                                     ↑  ↑
//                                                     Placeholders
```

**❌ NEVER concatenating SQL:**
```go
// NEVER do this!
query := "SELECT * FROM users WHERE username = '" + username + "'"
```

### 4. Token Security ✅

**✅ Cryptographically secure random:**
```go
rand.Read(b)  // crypto/rand, not math/rand
```

**✅ Token expiry:**
```go
expiry := time.Now().Add(24 * time.Hour)
```

**✅ Single use (cleared after use):**
```go
UPDATE users SET verification_token = NULL WHERE ...
```

### 5. Information Disclosure Prevention ✅

**✅ Generic error messages:**
```go
// Don't reveal if username exists
"Invalid username or password"  // Not "Username not found"
```

**✅ Same message for existing/non-existing emails:**
```go
"If an account exists with this email, a password reset link has been sent."
```

### 6. Email Verification Required ✅

**✅ Checking is_verified:**
```go
if !user.IsVerified {
	// Can't access protected pages
}
```

---

## 🎓 Common Attack Vectors (and how your code prevents them)

### 1. Brute Force Password Attacks

**Attack:** Try many passwords rapidly

**Your defense:**
- ✅ bcrypt is slow (100ms per attempt)
- ✅ Trying 1 million passwords = 27+ hours

**Could add:**
- Rate limiting (max 5 login attempts per minute)
- Account lockout after failed attempts
- CAPTCHA after multiple failures

### 2. Session Hijacking

**Attack:** Steal someone's session cookie

**Your defense:**
- ✅ HttpOnly = JavaScript can't access
- ✅ Secure = Only sent over HTTPS
- ✅ Encrypted = Can't be read or modified

### 3. SQL Injection

**Attack:** Inject malicious SQL code

**Your defense:**
- ✅ Always using `?` placeholders
- ✅ Database driver escapes inputs

**Example blocked attack:**
```go
username = "' OR '1'='1' --"

// With concatenation (VULNERABLE):
query = "SELECT * FROM users WHERE username = '" + username + "'"
// Becomes: SELECT * FROM users WHERE username = '' OR '1'='1' --'
// Returns ALL users!

// With placeholders (SAFE):
db.QueryRow("SELECT * FROM users WHERE username = ?", username)
// username treated as string value, not SQL code
```

### 4. Cross-Site Scripting (XSS)

**Attack:** Inject JavaScript into pages

**Your defense:**
- ✅ HTML template auto-escapes output
- ✅ HttpOnly cookies can't be stolen by scripts

**Example:**
```go
// User submits comment: <script>alert('XSS')</script>

// Template automatically escapes:
{{.Content}}
// Renders as: &lt;script&gt;alert('XSS')&lt;/script&gt;
// Shows as text, doesn't execute!
```

### 5. Cross-Site Request Forgery (CSRF)

**Attack:** Trick user into submitting malicious request

**Your defense:**
- ✅ SameSite cookies (modern browsers)
- ✅ Require logged-in session

**Could add:**
- CSRF tokens in forms

### 6. User Enumeration

**Attack:** Discover which emails are registered

**Your defense:**
- ✅ Same message whether email exists or not
- ✅ "If an account exists..." pattern

```go
// ❌ Reveals info
if emailExists {
	return "Reset link sent"
} else {
	return "Email not found"  // Attacker knows email not registered!
}

// ✅ Doesn't reveal info
return "If an account exists with this email, a password reset link has been sent."
```

---

## 📊 Complete Authentication Flow Diagram

```
┌──────────────────────────────────────────────────┐
│              USER REGISTRATION                   │
└──────────────────┬───────────────────────────────┘
                   ↓
         Fill registration form
                   ↓
         Submit → registerHandler
                   ↓
         ┌─────────────────────┐
         │ 1. Hash password    │
         │ 2. Generate token   │
         │ 3. Save to database │
         │ 4. Send email       │
         └─────────┬───────────┘
                   ↓
         User receives email
                   ↓
         Click verification link
                   ↓
         verifyHandler
                   ↓
         ┌─────────────────────┐
         │ 1. Check token      │
         │ 2. Set is_verified  │
         │ 3. Clear token      │
         └─────────┬───────────┘
                   ↓
         Email verified! ✅
                   ↓
┌──────────────────────────────────────────────────┐
│                   USER LOGIN                     │
└──────────────────┬───────────────────────────────┘
                   ↓
         Fill login form
                   ↓
         Submit → loginHandler
                   ↓
         ┌─────────────────────┐
         │ 1. Look up user     │
         │ 2. Verify password  │
         │ 3. Create session   │
         │ 4. Send cookie      │
         └─────────┬───────────┘
                   ↓
         Logged in! ✅
                   ↓
┌──────────────────────────────────────────────────┐
│              PROTECTED PAGES                     │
└──────────────────┬───────────────────────────────┘
                   ↓
         Visit /dashboard
                   ↓
         requireAuth middleware
                   ↓
         ┌─────────────────────┐
         │ 1. Read session     │
         │ 2. Get user ID      │
         │ 3. Query database   │
         │ 4. Check verified   │
         └─────────┬───────────┘
                   ↓
         ┌─YES─┐   │   ┌─NO──┐
         │     ↓       ↓      │
    dashboardHandler  Redirect /login
```

---

## 💡 Key Takeaways

✅ **bcrypt makes passwords uncrackable** - Never store plain passwords
✅ **Sessions remember logged-in users** - Encrypted cookies
✅ **Email verification prevents spam** - Users must own their email
✅ **Password reset is secure** - Tokens expire, single-use
✅ **Middleware protects routes** - requireAuth, requireAdmin
✅ **HttpOnly cookies prevent XSS theft** - JavaScript can't access
✅ **Secure cookies prevent interception** - Only sent over HTTPS
✅ **Parameterized queries prevent SQL injection** - Always use `?`
✅ **Generic error messages prevent enumeration** - Don't reveal info
✅ **Token expiry prevents replay attacks** - Limited time window

---

## 🚀 What's Next?

**You've completed the core learning materials!**

You now understand:
- ✅ Chapter 3: All imports and dependencies
- ✅ Chapter 4: Data structures (structs)
- ✅ Chapter 5: Database operations
- ✅ Chapter 6: HTTP routing and handlers
- ✅ Chapter 7: Authentication and security

**Additional topics to explore:**
- Gemini AI integration (how the chatbot works)
- HTML templates and frontend
- HTTPS and SSL certificates
- Deployment and production
- Testing and debugging

---

**Remember:** Security is not optional - it's fundamental! Your app follows industry best practices to keep user data safe. 🔐

---

*Congratulations on completing the learning materials! You're now ready to confidently modify and extend your Go application!* 🎉
