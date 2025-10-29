# Chapter 7: Authentication and Sessions

## Introduction

Authentication is how your app knows "who you are" (login), and sessions are how it "remembers" you across multiple page loads. This chapter covers the complete authentication flow in your application.

---

## The Authentication Flow

```
1. User registers (creates account)
    ↓
2. Email verification sent
    ↓
3. User clicks verification link
    ↓
4. Account marked as verified
    ↓
5. User logs in (username + password)
    ↓
6. Password verified with bcrypt
    ↓
7. Session created (cookie sent to browser)
    ↓
8. User makes requests (cookie included automatically)
    ↓
9. Server reads cookie → Knows who user is
    ↓
10. User logs out → Cookie deleted
```

---

## Section 1: Password Hashing with Bcrypt

### Why NOT Store Plain Passwords?

**❌ If database is breached:**
```
users table:
id | username | password
1  | john     | password123   ← Everyone can see it!
2  | jane     | qwerty
```

**✅ With hashing:**
```
users table:
id | username | password_hash
1  | john     | $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl...  ← Impossible to reverse!
2  | jane     | $2a$10$3fE2jLm9X...
```

### Hashing on Registration (Line 405)

```go
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
if err != nil {
    // Handle error
}

// Store hash in database
db.Exec("INSERT INTO users (..., password_hash) VALUES (..., ?)", ..., string(hashedPassword))
```

**What happens:**
```
User enters: "mypassword123"
    ↓
bcrypt.GenerateFromPassword()
    ↓
Generates: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
```

**Key properties:**
- **One-way:** Can't reverse the hash to get password
- **Unique:** Same password generates different hashes each time (salting)
- **Slow:** Takes ~100ms to generate (prevents brute force)

**Example:**
```go
bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
// First run:  $2a$10$abc123...
// Second run: $2a$10$xyz789...  ← Different hash!
```

### Verifying on Login (Line 470)

```go
var user User
// Fetch user from database (gets password_hash)
db.QueryRow("SELECT ..., password_hash FROM users WHERE username = ?", username).Scan(..., &user.PasswordHash)

// Compare submitted password with stored hash
err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
if err != nil {
    // Wrong password!
} else {
    // Correct password!
}
```

**How it works:**
```
User enters: "mypassword123"
    ↓
bcrypt.CompareHashAndPassword(
    storedHash: "$2a$10$N9qo...",  ← From database
    password:   "mypassword123"     ← User input
)
    ↓
Returns: nil (passwords match) or error (passwords don't match)
```

---

## Section 2: Email Verification Flow

### Why Verify Emails?

1. **Confirm real email** - User didn't typo
2. **Prevent spam** - Bots can't verify emails
3. **Enable password reset** - Know email works

### Generating Verification Tokens (Lines 417-418)

```go
token := generateToken()  // Random 64-character hex string
expiry := time.Now().Add(24 * time.Hour)  // Valid for 24 hours
```

**generateToken() function (Lines 1158-1162):**
```go
func generateToken() string {
    b := make([]byte, 32)  // 32 bytes
    rand.Read(b)           // Fill with cryptographically secure random bytes
    return hex.EncodeToString(b)  // Convert to hex: 64 characters
}
```

**Example tokens:**
```
a7f3b82c1e4d5f6a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c
f8e9d0c1b2a3948576a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0
```

**Why cryptographically secure?**
```go
// ❌ Predictable (DON'T USE)
token := fmt.Sprintf("%d", time.Now().Unix())  // "1640000000"

// ✅ Unpredictable (USE THIS)
crypto/rand.Read()  // Truly random
```

### Sending Verification Email (Lines 436-441)

```go
verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
// Result: "http://localhost:8080/verify?token=a7f3b82c..."

emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify your email: %s\n\nThis link expires in 24 hours.",
    username, verificationLink)

if err := sendEmail(email, "Verify Your Email", emailBody); err != nil {
    log.Printf("Failed to send verification email: %v", err)
}
```

**Email looks like:**
```
To: user@example.com
Subject: Verify Your Email

Welcome john_doe!

Click here to verify your email: http://localhost:8080/verify?token=a7f3b82c...

This link expires in 24 hours.
```

### Verifying Email (Lines 495-537)

```go
func verifyHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")  // Get token from URL
    if token == "" {
        // No token provided
        return
    }

    // Update user with matching token
    result, err := db.Exec(
        "UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = ? AND token_expiry > ?",
        token, time.Now(),
    )

    // Check if a row was updated
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        // Token invalid or expired
    } else {
        // Success!
    }
}
```

**SQL conditions:**
```sql
WHERE verification_token = ?     -- Token must match
AND token_expiry > ?             -- Must not be expired
```

**Outcomes:**
```
Token correct + Not expired → rowsAffected = 1 → Success
Token wrong → rowsAffected = 0 → Error
Token expired → rowsAffected = 0 → Error
Token already used (NULL) → rowsAffected = 0 → Error
```

---

## Section 3: Sessions (Staying Logged In)

### How Sessions Work

```
1. User logs in successfully
    ↓
2. Server creates session ID: "abc123xyz"
    ↓
3. Server stores: sessions["abc123xyz"] = {user_id: 42}
    ↓
4. Server sends cookie to browser:
   Set-Cookie: session=abc123xyz; HttpOnly; Secure
    ↓
5. Browser stores cookie
    ↓
6. Every request includes cookie automatically
    ↓
7. Server reads cookie: "abc123xyz"
    ↓
8. Server looks up: sessions["abc123xyz"] → {user_id: 42}
    ↓
9. Server knows: "This is user 42"
```

### Initializing Sessions (Lines 198-203)

```go
store = sessions.NewCookieStore([]byte(sessionKey))
store.Options = &sessions.Options{
    Path:     "/",          // Cookie valid for all pages
    MaxAge:   86400 * 7,    // 7 days in seconds
    HttpOnly: true,         // JavaScript cannot access (security)
}
```

**sessionKey** (line 32):
```go
const sessionKey = "a-very-secret-key-32-bytes-long"
```

**Why secret?**
- Cookies are encrypted with this key
- Without the key, attacker can't forge cookies
- ⚠️ Should be environment variable in production!

**MaxAge: 86400 * 7 seconds = 7 days**
```go
User logs in → Cookie expires in 7 days
User logs in again → Cookie refreshed for another 7 days
```

**HttpOnly: true**
```javascript
// JavaScript CANNOT do this:
document.cookie  // Won't see session cookie

// Prevents XSS attacks:
<script>
    // Attacker's script can't steal cookie!
</script>
```

### Creating a Session (Lines 481-485)

```go
// User just logged in successfully
session, _ := store.Get(r, "session")
session.Values["user_id"] = user.ID  // Store user ID in session
session.Save(r, w)                    // Send cookie to browser

http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```

**What happens:**
```
Browser                          Server
   │                                │
   │─── POST /login ────────────────→│ (username, password)
   │                                │
   │                            Verify password ✓
   │                            Create session
   │                            session["user_id"] = 42
   │                                │
   │←── Set-Cookie: session=abc... ─│
   │    Redirect to /dashboard      │
   │                                │
```

**Browser now has:**
```
Cookies:
  session=abc123xyz; expires=Fri, 22-Jan-2024; HttpOnly
```

### Reading a Session (Lines 331-345)

```go
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
```

**Flow:**
```
1. Get session from cookie
2. Extract user_id from session
3. Query database for user details
4. Return full User struct
```

**Every protected page calls this!**

### Destroying a Session (Logout) (Lines 488-493)

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    delete(session.Values, "user_id")  // Remove user_id from session
    session.Save(r, w)                  // Save changes (sends updated cookie)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

**What happens:**
```
Before: session.Values = {"user_id": 42}
After:  session.Values = {}  (empty)
```

**Browser's cookie is updated to empty session.**

---

## Section 4: Protecting Routes

### The requireAuth Middleware (Lines 347-367)

```go
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user, err := getCurrentUser(r)
        if err != nil {
            // Not logged in
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        if !user.IsVerified {
            // Email not verified
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

**Usage:**
```go
mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
mux.HandleFunc("/api/comment", requireAuth(commentHandler))
```

**Flow:**
```
User visits /dashboard
    ↓
requireAuth checks session
    ↓
If not logged in → Redirect to /login
If not verified → Show "verify email" message
If authenticated → Call dashboardHandler
```

**Passing user to handler:**
```go
ctx := context.WithValue(r.Context(), "user", user)
next(w, r.WithContext(ctx))
```

**Handler receives user:**
```go
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    user := r.Context().Value("user").(User)  // Get user from context
    // Use user...
}
```

### The requireAdmin Middleware (Lines 369-379)

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

**Checks:**
1. User is logged in
2. User has admin flag

**Usage:**
```go
mux.HandleFunc("/admin/", requireAdmin(adminHandler))
```

---

## Section 5: Security Considerations

### ✅ What Your Code Does Well

1. **Passwords hashed with bcrypt**
   ```go
   bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
   ```

2. **Cryptographically secure tokens**
   ```go
   crypto/rand.Read(b)  // Not predictable
   ```

3. **Token expiration**
   ```go
   expiry := time.Now().Add(24 * time.Hour)
   ```

4. **HttpOnly cookies**
   ```go
   HttpOnly: true  // JavaScript can't access
   ```

5. **Checks both authentication AND verification**
   ```go
   if err != nil { /* not logged in */ }
   if !user.IsVerified { /* not verified */ }
   ```

### ⚠️ Potential Improvements

1. **HTTPS only** (currently HTTP)
   ```go
   store.Options = &sessions.Options{
       Secure: true,  // Only send over HTTPS
   }
   ```

2. **Session key from environment**
   ```go
   // ❌ Hardcoded
   const sessionKey = "a-very-secret-key-32-bytes-long"

   // ✅ From environment
   sessionKey := os.Getenv("SESSION_KEY")
   ```

3. **Rate limiting login attempts**
   ```go
   // Prevent brute force attacks
   if attempts > 5 {
       // Block for 15 minutes
   }
   ```

4. **Password strength requirements**
   ```go
   if len(password) < 8 {
       return errors.New("password must be at least 8 characters")
   }
   ```

5. **Two-factor authentication (2FA)**
   ```go
   // Optional: Send code to phone
   ```

---

## Complete Authentication Example

### Registration → Verification → Login

**1. User Registers:**
```go
// POST /register
username: "john"
email: "john@example.com"
password: "password123"
    ↓
hashedPassword = bcrypt.GenerateFromPassword("password123")
token = generateToken()  // "a7f3b82c..."
expiry = time.Now().Add(24 * time.Hour)
    ↓
INSERT INTO users (username, email, password_hash, verification_token, token_expiry, is_verified)
VALUES ("john", "john@example.com", "$2a$10$...", "a7f3b82c...", "2024-01-16 10:00:00", FALSE)
    ↓
Email sent with link: http://localhost:8080/verify?token=a7f3b82c...
```

**2. User Clicks Email Link:**
```go
// GET /verify?token=a7f3b82c...
    ↓
UPDATE users
SET is_verified = TRUE, verification_token = NULL
WHERE verification_token = "a7f3b82c..." AND token_expiry > NOW()
    ↓
1 row updated → Success!
```

**3. User Logs In:**
```go
// POST /login
username: "john"
password: "password123"
    ↓
SELECT id, password_hash, is_verified FROM users WHERE username = "john"
    ↓
bcrypt.CompareHashAndPassword(stored_hash, "password123")  → Match!
    ↓
session.Values["user_id"] = 1
session.Save()  → Set-Cookie: session=xyz789...
    ↓
Redirect to /dashboard
```

**4. User Visits Dashboard:**
```go
// GET /dashboard
Cookie: session=xyz789...
    ↓
requireAuth middleware:
    session = store.Get(r, "session")
    userID = session.Values["user_id"]  // 1
    user = getCurrentUser()  // Query DB for user 1
    ↓
dashboardHandler renders page with user data
```

**5. User Logs Out:**
```go
// GET /logout
Cookie: session=xyz789...
    ↓
session.Values["user_id"] = deleted
session.Save()  → Set-Cookie: session=xyz789... (but empty)
    ↓
Redirect to /
```

---

## Practice Exercises

### Exercise 1: Check if User is Logged In

```go
func someHandler(w http.ResponseWriter, r *http.Request) {
    user, err := getCurrentUser(r)
    if err != nil {
        // What should you do?
    }
}
```

**Answer:**
```go
if err != nil {
    // User not logged in
    http.Redirect(w, r, "/login", http.StatusSeeOther)
    return
}
```

### Exercise 2: Verify Password

Check if password "mypassword" matches hash "$2a$10$abc...":

**Answer:**
```go
err := bcrypt.CompareHashAndPassword([]byte("$2a$10$abc..."), []byte("mypassword"))
if err != nil {
    fmt.Println("Wrong password")
} else {
    fmt.Println("Correct password")
}
```

---

## Key Takeaways

✅ **Never store plain passwords** - Use bcrypt
✅ **Bcrypt is one-way** - Can't reverse the hash
✅ **Tokens must be random** - Use crypto/rand
✅ **Sessions use cookies** - Automatically included in requests
✅ **HttpOnly cookies** - JavaScript can't access
✅ **MaxAge** - Sessions expire after 7 days
✅ **Middleware** - Protects routes (requireAuth, requireAdmin)
✅ **Context** - Passes user data to handlers
✅ **Email verification** - Confirms real email address

---

**Next Chapter:** Middleware patterns - wrapping handlers to add functionality!
