# Chapter 3: Imports and Dependencies 📦

## Welcome Back!

In this chapter, we'll explore every single import in your `main.go` file. Think of imports as tools in a toolbox - each one gives your program special abilities!

---

## 📍 Finding the Imports

Look at **lines 3-21** in your `main.go`:

```go
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
```

You have **18 imports total**:
- **15 from Go's standard library** (built-in, free!)
- **3 external packages** (need to download)

---

## 🎯 Why Do We Need Imports?

Go keeps things simple. Instead of including everything by default, you only import what you need. This makes your program:
- ✅ Faster to compile
- ✅ Smaller in size
- ✅ Easier to understand

Think of it like packing for a trip - you only bring what you'll actually use!

---

## 📚 Standard Library Imports (Built into Go)

### 1. `bytes` - Working with Byte Data

**📍 Location in code:** Line 3
**🎯 What it does:** Handles raw byte data (binary information)

**Where you use it (Line 1094 & 1115):**
```go
// Creating a bytes buffer for HTTP request
reqBody := bytes.NewBuffer(jsonData)
resp, err := http.Post(geminiAPIURL, "application/json", reqBody)
```

**🤔 Why bytes?**
When sending data over the internet, everything becomes bytes (0s and 1s). The `bytes` package helps you work with this raw data.

**Real-world analogy:**
Imagine you're sending a letter. You write it (string), then put it in an envelope (bytes) to mail it.

**Beginner tip:** You'll use this mostly when making HTTP requests to external APIs.

---

### 2. `context` - Request Context & Data Passing

**📍 Location in code:** Line 4
**🎯 What it does:** Carries information through your program, especially useful for web requests

**Where you use it (Lines 359-366):**
```go
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := getCurrentUser(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Put user info in the context
		ctx := context.WithValue(r.Context(), "user", user)
		next(w, r.WithContext(ctx))
	}
}
```

**🤔 Why context?**
Context is like a backpack that travels with each web request. You can put things in it (like user info) and take them out later!

**Visual example:**
```
Step 1: User visits /dashboard
   ↓
Step 2: requireAuth middleware adds user to context
   ↓
Step 3: dashboardHandler reads user from context
   ↓
Step 4: Shows personalized dashboard
```

**Where you retrieve it (Line 548):**
```go
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context (put there by requireAuth)
	user := r.Context().Value("user").(User)
	// Now we know who's logged in!
}
```

**Beginner tip:** Context is perfect for middleware patterns. It lets you pass data between functions without global variables.

---

### 3. `crypto/rand` - Secure Random Numbers

**📍 Location in code:** Line 5
**🎯 What it does:** Generates truly random numbers for security purposes

**Where you use it (Lines 1201-1205):**
```go
func generateToken() string {
	b := make([]byte, 32) // Create space for 32 random bytes
	rand.Read(b)          // Fill with random data
	return hex.EncodeToString(b) // Convert to readable text
}
```

**🤔 Why is randomness important?**

❌ **Bad randomness (predictable):**
```
Token: abc123
Next token: abc124  ← Hacker can guess!
```

✅ **Good randomness (crypto/rand):**
```
Token: a7f3b82c4d9e1f...  ← Impossible to guess!
```

**Where you use these tokens:**
- Email verification (Line 432): So only the real user can verify their email
- Password reset (Line 508): So only the real user can reset their password

**Real-world analogy:**
Using `crypto/rand` is like using a casino-grade dice that's perfectly balanced. Using regular random numbers is like using loaded dice - someone could predict the result!

**Beginner tip:** Always use `crypto/rand` for anything security-related (tokens, keys, etc.). Never use `math/rand` for security!

---

### 4. `database/sql` - Database Connection

**📍 Location in code:** Line 6
**🎯 What it does:** Provides a standard way to talk to databases

**Where you use it (Line 42):**
```go
var db *sql.DB  // This holds your database connection
```

**Initialize database (Lines 281-296):**
```go
func initDB(filepath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", filepath)  // Open connection
	if err != nil {
		return nil, err
	}

	// Test the connection works
	if err = db.Ping(); err != nil {
		return nil, err
	}

	// ... create tables ...
	return db, nil
}
```

**🤔 Important concept: Connection Pool**

Your app doesn't open a new database connection for every request. Instead, `*sql.DB` manages a **pool** of connections:

```
Request 1 ──→ Connection A
Request 2 ──→ Connection B
Request 3 ──→ Connection A (reused!)
Request 4 ──→ Connection B (reused!)
```

**Three main operations:**

1. **Query (get multiple rows) - Line 597:**
```go
rows, err := db.Query("SELECT id, username, email FROM users")
```

2. **QueryRow (get one row) - Line 338:**
```go
err := db.QueryRow("SELECT id, username, email FROM users WHERE id = ?", userID)
```

3. **Exec (insert/update/delete) - Line 367:**
```go
db.Exec("ALTER TABLE users ADD COLUMN password_reset_token TEXT")
```

**Beginner tip:** `database/sql` is just the interface. You need a driver (like go-sqlite3) to actually talk to SQLite.

---

### 5. `encoding/hex` - Hexadecimal Encoding

**📍 Location in code:** Line 7
**🎯 What it does:** Converts between bytes and hex strings

**Where you use it (Line 1204):**
```go
return hex.EncodeToString(b)
```

**🤔 What is hexadecimal?**

Hexadecimal (hex) uses 16 digits: 0-9 and a-f

**Conversion example:**
```
Random bytes: [167, 243, 184, 44, ...]
       ↓ hex.EncodeToString()
Hex string: "a7f3b82c..."
```

**Why use hex for tokens?**
- ✅ Compact (2 hex chars = 1 byte)
- ✅ URL-safe (only 0-9, a-f)
- ✅ Easy to copy/paste in emails

**Real example from your code:**
```
32 random bytes → 64 character hex token
Used in verification email:
https://explorer.needgreatersglobal.com/verify?token=a7f3b82c...
```

---

### 6. `encoding/json` - JSON Data Format

**📍 Location in code:** Line 8
**🎯 What it does:** Converts Go data to/from JSON (JavaScript Object Notation)

**Why JSON?**
JSON is the universal language of web APIs. When your browser talks to your Go server, they speak JSON!

**Example JSON:**
```json
{
  "status": "success",
  "message": "Place submitted for review"
}
```

**Encoding (Go → JSON) - Line 931:**
```go
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{
	"status":  "success",
	"message": "Place submitted for review",
})
```

**Decoding (JSON → Go) - Line 998:**
```go
var req AIChatRequest
json.NewDecoder(r.Body).Decode(&req)
// Now req.Prompt contains the user's message!
```

**🤔 How does JSON know field names?**

Look at your structs (Lines 154-157):
```go
type AIChatRequest struct {
	Prompt string `json:"prompt"`  // ← This tag!
}
```

The `` `json:"prompt"` `` tells JSON:
- Go uses: `Prompt` (capitalized, public)
- JSON uses: `"prompt"` (lowercase)

**Beginner tip:** JSON tags are SUPER important. Without them, your field would be called "Prompt" in JSON, which might not match what JavaScript expects!

---

### 7. `fmt` - Formatted Printing

**📍 Location in code:** Line 9
**🎯 What it does:** Format strings and print output (like printf in other languages)

**Common uses in your code:**

**1. Building URLs (Line 436):**
```go
verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
// Result: "https://explorer.needgreatersglobal.com/verify?token=abc123..."
```

**2. Creating error messages (Line 335):**
```go
return User{}, fmt.Errorf("no valid session")
```

**3. Building email messages (Line 437):**
```go
emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify your email: %s",
	username, verificationLink)
```

**🤔 Format verbs (the % things):**

| Verb | Meaning | Example |
|------|---------|---------|
| `%s` | String | `fmt.Sprintf("Hello %s", "world")` → "Hello world" |
| `%d` | Integer | `fmt.Sprintf("Count: %d", 42)` → "Count: 42" |
| `%f` | Float | `fmt.Sprintf("Price: %.2f", 3.14159)` → "Price: 3.14" |
| `%v` | Any value | `fmt.Sprintf("Value: %v", anything)` |

**Beginner tip:** `%s` is for strings, `%d` is for whole numbers. That's 90% of what you'll use!

---

### 8. `html/template` - HTML Template Engine

**📍 Location in code:** Line 10
**🎯 What it does:** Safely generates HTML pages from templates

**Where you initialize it (Lines 206-213):**
```go
tpl = template.Must(template.New("main").Funcs(template.FuncMap{
	"safeHTML": func(s string) template.HTML {
		return template.HTML(s)
	},
	"formatTime": func(t time.Time) string {
		return t.Format("Jan 2, 2006 at 3:04 PM")
	},
}).Parse(allTemplates))
```

**🤔 Why templates?**

**Without templates (BAD ❌):**
```go
html := "<h1>Welcome " + username + "</h1>"  // XSS vulnerability!
```

**With templates (GOOD ✅):**
```html
<h1>Welcome {{.Username}}</h1>  <!-- Auto-escaped, safe! -->
```

**Where you use it (Line 1195):**
```go
func renderTemplate(w http.ResponseWriter, tmplName string, data PageBundle) {
	err := tpl.ExecuteTemplate(w, tmplName, data)
}
```

**Custom functions you added:**
1. **safeHTML** - Allows HTML when you actually want it
2. **formatTime** - Formats dates nicely: "Jan 15, 2024 at 3:45 PM"

**Real example (Line 412):**
```go
renderTemplate(w, "register", PageBundle{
	Data: MessagePageData{
		Title:   "Registration Error",
		Message: "Username or email already exists.",
	},
})
```

**Beginner tip:** Templates prevent XSS attacks automatically by escaping user input. This means if a user tries to inject `<script>alert('hack')</script>`, it shows as text instead of running!

---

### 9. `log` - Logging Messages

**📍 Location in code:** Line 11
**🎯 What it does:** Prints messages to the console with timestamps

**Where you use it:**

**Success messages (Line 268):**
```go
log.Println("Database initialized and tables created.")
```
Output: `2024/01/15 10:30:45 Database initialized and tables created.`

**Fatal errors (stops program) - Line 263:**
```go
log.Fatal("Failed to initialize database:", err)
```
Output: `2024/01/15 10:30:45 Failed to initialize database: unable to open database file`
Then program exits.

**Error logging (continues running) - Line 440:**
```go
log.Printf("Failed to send verification email: %v", err)
```

**🤔 Log levels in your code:**

| Function | When to use | Program continues? |
|----------|------------|-------------------|
| `log.Println()` | Success info | ✅ Yes |
| `log.Printf()` | Formatted messages | ✅ Yes |
| `log.Fatal()` | Critical errors | ❌ No, exits immediately |

**Beginner tip:** Use `log.Fatal()` only for errors that mean the app can't continue (like database connection failure). Use `log.Printf()` for errors you can recover from.

---

### 10. `net/http` - Web Server & Client

**📍 Location in code:** Line 12
**🎯 What it does:** This is THE package that makes your app a web server!

**Three main uses:**

**1. Starting the server (Line 221):**
```go
http.ListenAndServeTLS(":443", certFile, keyFile, mux)
// Listens on port 443 (HTTPS) with SSL certificates
```

**2. Routing requests (Lines 228-249):**
```go
mux.HandleFunc("/", homeHandler)
mux.HandleFunc("/login", loginHandler)
mux.HandleFunc("/api/chat", chatAPIHandler)
```

**3. Handler functions receive two things:**
```go
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// w = Write response to user
	// r = Read request from user
}
```

**🤔 How a web request works:**

```
1. User types: https://yoursite.com/login
   ↓
2. Browser sends HTTP Request
   ↓
3. Your mux routes it to loginHandler
   ↓
4. loginHandler processes it
   ↓
5. Sends HTTP Response back
   ↓
6. Browser displays the page
```

**Reading form data (Line 399):**
```go
username := r.FormValue("username")
email := r.FormValue("email")
password := r.FormValue("password")
```

**Redirecting (Line 485):**
```go
http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```

**Making HTTP requests to other servers (Line 1116):**
```go
resp, err := http.Post(geminiAPIURL, "application/json", reqBody)
```

**Beginner tip:** `net/http` is incredibly powerful. It handles the complex networking stuff so you can focus on your app logic!

---

### 11. `net/smtp` - Sending Emails

**📍 Location in code:** Line 13
**🎯 What it does:** Sends emails through an SMTP server

**Your email settings (Lines 25-29):**
```go
const (
	smtpHost     = "mail.needgreatersglobal.com"
	smtpPort     = "587"
	smtpEmail    = "endrig@needgreatersglobal.com"
	smtpPassword = "Assembly3637997Ab,"
)
```

**Where you send emails (Lines 1207-1215):**
```go
func sendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", smtpEmail, smtpPassword, smtpHost)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s",
		to, subject, body))

	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	return smtp.SendMail(addr, auth, smtpEmail, []string{to}, msg)
}
```

**🤔 When you send emails:**

1. **Registration verification (Line 439):**
```go
emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify your email: %s",
	username, verificationLink)
sendEmail(email, "Verify Your Email", emailBody)
```

2. **Password reset (Line 515):**
```go
emailBody := fmt.Sprintf("Hello %s,\n\nYou requested a password reset. Click the link below...",
	username)
sendEmail(email, "Password Reset Request", emailBody)
```

**Email flow:**
```
Your App → SMTP Server (port 587) → Recipient's Inbox
```

**Beginner tip:** Port 587 uses STARTTLS encryption. This means your emails (and password!) are encrypted during transmission.

---

### 12. `strconv` - String/Number Conversion

**📍 Location in code:** Line 14
**🎯 What it does:** Converts strings to numbers and vice versa

**Why needed?**
Form data and URLs are always strings, but you often need numbers for database IDs!

**String to integer (Line 580):**
```go
userID, _ := strconv.Atoi(r.FormValue("user_id"))
// "42" → 42
```

**String to float (Line 632):**
```go
lat, _ := strconv.ParseFloat(r.FormValue("latitude"), 64)
// "42.8765" → 42.8765
```

**🤔 Common functions:**

| Function | Purpose | Example |
|----------|---------|---------|
| `Atoi(s)` | String → Int | `strconv.Atoi("42")` → `42` |
| `Itoa(i)` | Int → String | `strconv.Itoa(42)` → `"42"` |
| `ParseFloat(s, 64)` | String → Float | `strconv.ParseFloat("3.14", 64)` → `3.14` |
| `ParseBool(s)` | String → Bool | `strconv.ParseBool("true")` → `true` |

**Notice the error handling pattern (Line 580):**
```go
userID, _ := strconv.Atoi(r.FormValue("user_id"))
```
The `_` ignores errors. If conversion fails, `userID` will be 0.

**Better pattern (more cautious):**
```go
userID, err := strconv.Atoi(r.FormValue("user_id"))
if err != nil {
	// Handle error: not a valid number
}
```

**Beginner tip:** URLs and forms give you strings. Database IDs are integers. `strconv` is the bridge between them!

---

### 13. `strings` - String Manipulation

**📍 Location in code:** Line 15
**🎯 What it does:** Common string operations

**Where you use it:**

**1. Splitting strings (Line 819):**
```go
pathParts := strings.Split(r.URL.Path, "/")
// "/place/42" → ["", "place", "42"]
placeID := pathParts[2] // Gets "42"
```

**2. Converting to lowercase (Line 768):**
```go
searchParam := "%" + strings.ToLower(searchQuery) + "%"
// "CASTLES" → "castles" (for case-insensitive search)
```

**3. Checking if substring exists (Line 1053):**
```go
if strings.Contains(lowerPrompt, "consultation") ||
   strings.Contains(lowerPrompt, "booking") {
	return "counseling"
}
```

**4. Trimming whitespace (Line 1037):**
```go
classification := strings.TrimSpace(text)
// "  places  " → "places"
```

**🤔 Common string functions:**

| Function | Purpose | Example |
|----------|---------|---------|
| `Contains(s, sub)` | Check substring | `strings.Contains("hello", "ell")` → `true` |
| `Split(s, sep)` | Split into parts | `strings.Split("a,b,c", ",")` → `["a","b","c"]` |
| `ToLower(s)` | Lowercase | `strings.ToLower("HeLLo")` → `"hello"` |
| `ToUpper(s)` | Uppercase | `strings.ToUpper("hello")` → `"HELLO"` |
| `TrimSpace(s)` | Remove spaces | `strings.TrimSpace("  hi  ")` → `"hi"` |
| `Join(slice, sep)` | Join strings | `strings.Join(["a","b"], ",")` → `"a,b"` |

**Real example from your AI classifier (Lines 1046-1054):**
```go
lowerPrompt := strings.ToLower(prompt)

counselingKeywords := []string{"counseling", "counsel", "therapy", ...}
for _, keyword := range counselingKeywords {
	if strings.Contains(lowerPrompt, keyword) {
		return "counseling"
	}
}
```

**Beginner tip:** Always use `strings.ToLower()` before comparing user input. Users might type "HELLO", "hello", or "HeLLo"!

---

### 14. `time` - Time and Dates

**📍 Location in code:** Line 16
**🎯 What it does:** Work with dates, times, and durations

**Where you use it:**

**1. Getting current time (Line 418):**
```go
expiry := time.Now().Add(24 * time.Hour)
// Current time + 24 hours
```

**2. Time in database tables (Line 303):**
```sql
created_at DATETIME DEFAULT CURRENT_TIMESTAMP
```

**3. Struct fields (Lines 73, 100):**
```go
TokenExpiry sql.NullTime  // Can be NULL in database
CreatedAt   time.Time     // Always has a value
```

**4. Custom time formatting (Line 211):**
```go
"formatTime": func(t time.Time) string {
	return t.Format("Jan 2, 2006 at 3:04 PM")
},
```

**🤔 Go's weird date format:**

Instead of `YYYY-MM-DD`, Go uses a **reference date**: Jan 2, 2006 at 3:04:05 PM MST

Why? It's 01/02 03:04:05 PM '06 -07 (sequential!)

**Examples:**
```go
t.Format("2006-01-02")              // "2024-01-15"
t.Format("Jan 2, 2006")             // "Jan 15, 2024"
t.Format("3:04 PM")                 // "10:30 AM"
t.Format("Monday, Jan 2, 2006")     // "Monday, Jan 15, 2024"
```

**Durations:**
```go
24 * time.Hour        // 24 hours
30 * time.Minute      // 30 minutes
5 * time.Second       // 5 seconds
```

**Comparing times (Line 509):**
```go
// Find users where token hasn't expired
WHERE token_expiry > ?", time.Now()
```

**Beginner tip:** Store times in the database as strings, but work with them in Go as `time.Time` for easy comparisons and formatting!

---

## 🔧 External Dependencies (Must Install)

### 15. `github.com/gorilla/sessions` - Session Management

**📍 Location in code:** Line 18
**🎯 What it does:** Keeps users logged in across pages

**Installation:**
```bash
go get github.com/gorilla/sessions
```

**What are sessions?**

Without sessions, the server doesn't "remember" who you are. Every page load, you'd have to log in again! Sessions solve this.

**How sessions work:**
```
1. User logs in successfully
   ↓
2. Server creates a session
   session.Values["user_id"] = 42
   ↓
3. Server sends encrypted cookie to browser
   Cookie: session=abc123...
   ↓
4. Browser includes cookie in future requests
   ↓
5. Server decrypts cookie, sees user_id=42
   "Oh, this is user 42, they're logged in!"
```

**Setting up sessions (Lines 198-203):**
```go
store = sessions.NewCookieStore([]byte(sessionKey))
store.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   86400 * 7, // 7 days in seconds
	HttpOnly: true,      // Can't be accessed by JavaScript
	Secure:   true,      // Only send over HTTPS
}
```

**Creating a session (Lines 481-483):**
```go
session, _ := store.Get(r, "session")
session.Values["user_id"] = user.ID  // Remember this user
session.Save(r, w)                    // Send cookie to browser
```

**Reading a session (Lines 332-336):**
```go
session, _ := store.Get(r, "session")
userID, ok := session.Values["user_id"].(int)
if !ok || userID == 0 {
	return User{}, fmt.Errorf("no valid session")
}
```

**Logging out (Lines 488-491):**
```go
session, _ := store.Get(r, "session")
delete(session.Values, "user_id")  // Forget user
session.Save(r, w)
```

**🤔 Security features:**
- **HttpOnly** - JavaScript can't steal your cookie
- **Secure** - Cookie only sent over HTTPS
- **Encrypted** - Cookie value is encrypted with `sessionKey`

**Beginner tip:** Never store passwords in sessions! Only store the user ID, then look up user info from the database when needed.

---

### 16. `github.com/mattn/go-sqlite3` - SQLite Database Driver

**📍 Location in code:** Line 19
**🎯 What it does:** Allows Go to talk to SQLite databases

**Installation:**
```bash
go get github.com/mattn/go-sqlite3
```

**The mysterious underscore import:**
```go
_ "github.com/mattn/go-sqlite3" // SQLite driver
```

**🤔 Why the underscore `_`?**

You never directly call functions from this package:
```go
// You DON'T do this:
sqlite3.Connect(...)  // ❌ Not how it works
```

Instead, it **registers itself** with `database/sql`:
```go
// You DO this:
db, err := sql.Open("sqlite3", "./users.db")  // ✅ Uses the driver automatically
```

**How it works behind the scenes:**
```
1. Import go-sqlite3
   ↓
2. Its init() function runs automatically
   ↓
3. Registers itself as "sqlite3" driver
   ↓
4. sql.Open("sqlite3", ...) now knows what to do
```

**Why SQLite?**
- ✅ No separate database server needed
- ✅ Database is just one file: `users.db`
- ✅ Perfect for small-medium applications
- ✅ Easy backup: just copy the file!

**Your database file (Line 261):**
```go
db, err = initDB("./users.db")
```

**Beginner tip:** The `_` import is called a "blank import" - used when you need the package's side effects (like registering a driver) but don't call its functions directly.

---

### 17. `golang.org/x/crypto/bcrypt` - Password Hashing

**📍 Location in code:** Line 20
**🎯 What it does:** Securely hashes and verifies passwords

**Installation:**
```bash
go get golang.org/x/crypto/bcrypt
```

**🤔 Why can't we store passwords directly?**

**❌ BAD - Plain text passwords:**
```
Database:
- alice: password123
- bob:   qwerty

If hacker steals database → Game over! All passwords leaked!
```

**✅ GOOD - Hashed passwords:**
```
Database:
- alice: $2a$10$N9qo8uLOickgx2ZMRZoMye...
- bob:   $2a$10$7hFn3XJ9mRkKNGf8g2jN4e...

If hacker steals database → Can't reverse hashes to get passwords!
```

**Hashing a password (Line 405):**
```go
hashedPassword, err := bcrypt.GenerateFromPassword(
	[]byte(password),
	bcrypt.DefaultCost,
)
// "mypassword123" → "$2a$10$N9qo8uLOickgx2ZMRZoMye..."
```

**Verifying a password (Line 470):**
```go
err := bcrypt.CompareHashAndPassword(
	[]byte(user.PasswordHash),  // From database
	[]byte(password),            // User typed this
)
if err != nil {
	// Wrong password!
}
```

**🤔 What makes bcrypt special?**

1. **Slow by design** - Takes ~100ms to hash one password
   - For normal login: 100ms is fine
   - For attacker trying 1 million passwords: 100,000 seconds = 27 hours!

2. **Automatically salted** - Each hash is unique, even for same password
   ```
   "password123" → $2a$10$abc...
   "password123" → $2a$10$xyz...  (different hash!)
   ```

3. **Adaptive** - Can increase difficulty as computers get faster
   ```go
   bcrypt.GenerateFromPassword(pwd, 10)  // Easier
   bcrypt.GenerateFromPassword(pwd, 14)  // Harder
   ```

**Hash anatomy:**
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
 │   │  │
 │   │  └─ Random salt
 │   └──── Cost (difficulty)
 └──────── Algorithm version
```

**Beginner tip:** NEVER try to decrypt bcrypt hashes - it's mathematically impossible! You can only verify: "Is this password correct for this hash?"

---

## 📦 Managing Dependencies

### The go.mod File

Your project should have a `go.mod` file:

```bash
cd /c/Users/user/Documents/Clients/affiliate
cat go.mod
```

**Example go.mod:**
```
module affiliate

go 1.21

require (
	github.com/gorilla/sessions v1.2.1
	github.com/mattn/go-sqlite3 v1.14.18
	golang.org/x/crypto v0.16.0
)
```

### Installing All Dependencies

```bash
# Download all dependencies
go mod download

# Or just build (auto-downloads)
go build main.go
```

### Adding New Dependencies

```bash
# Add a new package
go get github.com/some/package

# Update all dependencies
go get -u ./...
```

---

## 🎯 Import Best Practices

### 1. Import Grouping ✅

Your code already follows Go conventions:
```go
import (
	// Standard library imports (alphabetical)
	"bytes"
	"context"
	"crypto/rand"
	// ...

	// External packages (alphabetical)
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)
```

### 2. Unused Imports ❌

Go is strict - you can't import something you don't use!

```go
import "fmt"  // ❌ Compile error if you never use fmt
```

**Exception:** Blank imports for side effects:
```go
import _ "github.com/mattn/go-sqlite3"  // ✅ OK
```

### 3. Import Aliases

Sometimes you need two packages with same name:
```go
import (
	cryptorand "crypto/rand"  // Alias to avoid conflict
	mathrand "math/rand"
)

// Now you can use both:
cryptorand.Read(b)
mathrand.Intn(100)
```

---

## 🗺️ Dependency Map

```
Your main.go
    │
    ├── Standard Library (Built-in)
    │   ├── net/http → Web server & routing
    │   ├── database/sql → Database interface
    │   ├── encoding/json → API responses
    │   ├── html/template → Render HTML pages
    │   ├── crypto/rand → Secure tokens
    │   ├── time → Timestamps & expiry
    │   └── ... (9 more)
    │
    └── External Packages (Need install)
        ├── gorilla/sessions → User sessions
        ├── go-sqlite3 → SQLite database
        └── bcrypt → Password hashing
```

---

## 📊 Import Summary Table

| Package | Type | Purpose | Key Lines |
|---------|------|---------|-----------|
| `bytes` | Standard | HTTP request bodies | 1094, 1115 |
| `context` | Standard | Pass user data through middleware | 359-366 |
| `crypto/rand` | Standard | Generate secure tokens | 1201-1205 |
| `database/sql` | Standard | Database operations | Throughout |
| `encoding/hex` | Standard | Convert bytes to hex strings | 1204 |
| `encoding/json` | Standard | JSON APIs | 931, 998 |
| `fmt` | Standard | String formatting | 436, 437, 515 |
| `html/template` | Standard | Render HTML safely | 206-213, 1195 |
| `log` | Standard | Console logging | 263, 268, 440 |
| `net/http` | Standard | Web server | 221, 228-249 |
| `net/smtp` | Standard | Send emails | 1207-1215 |
| `strconv` | Standard | String ↔ number conversion | 580, 632 |
| `strings` | Standard | String manipulation | 768, 819, 1053 |
| `time` | Standard | Dates and durations | 418, 509 |
| `gorilla/sessions` | External | User sessions | 198-203, 332-336 |
| `go-sqlite3` | External | SQLite driver | 261 (indirectly) |
| `bcrypt` | External | Password hashing | 405, 470 |

---

## 🎓 Practice Exercise

**Test your understanding! Match each package to its real-world use:**

1. User logs in → Which package stores session?
2. User registers → Which package hashes password?
3. Email verification → Which package generates token?
4. Browser requests /places → Which package routes it?
5. Store new place in database → Which package executes SQL?

**Answers:**
1. `gorilla/sessions` - Keeps user logged in
2. `bcrypt` - Hashes password securely
3. `crypto/rand` + `encoding/hex` - Creates random token
4. `net/http` - Routes URL to handler
5. `database/sql` + `go-sqlite3` - Executes SQL query

---

## 💡 Key Takeaways

✅ **Standard library is powerful** - 15 of your 18 imports are built-in!
✅ **External dependencies are strategic** - Only 3 external packages for critical features
✅ **Each import has a purpose** - No bloat, just what you need
✅ **Context is magical** - Passes data between middleware and handlers
✅ **Always use crypto/rand for security** - Never math/rand!
✅ **Bcrypt is your password guardian** - Never store plain passwords
✅ **Gorilla sessions keep users logged in** - Secure, encrypted cookies

---

## 🚀 Next Steps

Now that you understand what tools your code uses, let's see how they work together!

**Next chapter:** [Structs and Data Models](04-structs-and-data-models.md)
We'll explore how your data is organized and structured.

---

**Remember:** Imports are like Lego blocks - each one adds specific capabilities. Your code uses 18 carefully chosen blocks to build a complete web application! 🏗️

---

*Happy coding! Next up: Understanding your data structures* 📦➡️🏗️
