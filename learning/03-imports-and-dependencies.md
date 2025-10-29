# Chapter 3: Imports and Dependencies

## Introduction

At the top of your `main.go` (lines 3-22), you import various packages. This chapter explains what each one does and why it's needed. Think of imports as "superpowers" you add to your program!

---

## Understanding the Import Block (Lines 3-22)

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

---

## Standard Library Imports

These come built into Go - no installation needed!

### 1. `bytes` - Working with Byte Slices

**What it does:** Manipulates byte slices (raw binary data)

**Used in your code (line 1064):**
```go
resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
```

**Why:** When sending HTTP requests, data must be in byte format. `bytes.NewBuffer()` creates a reader from byte data.

**Common use cases:**
- HTTP request bodies
- Building strings efficiently
- Binary data manipulation

---

### 2. `context` - Request Context and Cancellation

**What it does:** Carries deadlines, cancellation signals, and request-scoped values across API boundaries

**Used in your code (lines 364, 376):**
```go
ctx := context.WithValue(r.Context(), "user", user)
next(w, r.WithContext(ctx))
```

**Why:** Passes data (like the current user) from middleware to handlers without global variables.

**Visualization:**
```
Middleware (requireAuth)
    ↓ Adds user to context
Handler (dashboardHandler)
    ↓ Reads user from context
```

**Key concept:**
- Each HTTP request has a `context`
- You can store values in it: `context.WithValue()`
- You can retrieve values: `r.Context().Value("user")`

**Other uses** (not in your code):
- Timeouts: `ctx, cancel := context.WithTimeout(...)`
- Cancellation: When a user disconnects, clean up resources

---

### 3. `crypto/rand` - Secure Random Number Generation

**What it does:** Generates cryptographically secure random bytes

**Used in your code (line 1160):**
```go
func generateToken() string {
    b := make([]byte, 32)
    rand.Read(b)  // Fill with random bytes
    return hex.EncodeToString(b)
}
```

**Why secure randomness matters:**
- ❌ `math/rand` - Predictable, good for games
- ✅ `crypto/rand` - Unpredictable, good for security

**Your use case:** Email verification tokens must be impossible to guess. If someone could predict tokens, they could verify any account!

**Example token:** `a7f3b82c...` (64 hex characters)

---

### 4. `database/sql` - Database Interface

**What it does:** Provides a generic interface for SQL databases

**Used throughout your code:**
```go
var db *sql.DB  // Database connection

db.Query("SELECT ...")      // Multiple rows
db.QueryRow("SELECT ...")   // Single row
db.Exec("INSERT INTO ...")  // Modify data
```

**Important:** This package is just an **interface**. You need a **driver** for your specific database (see SQLite import below).

**Key types:**
- `*sql.DB` - Database connection pool
- `sql.NullString` - String that can be NULL
- `sql.NullTime` - Time that can be NULL

**Connection pooling:**
`*sql.DB` automatically manages multiple connections:
```
User 1 request → Connection 1
User 2 request → Connection 2
User 3 request → Connection 1 (reused)
```

---

### 5. `encoding/hex` - Hexadecimal Encoding

**What it does:** Converts bytes to/from hexadecimal strings

**Used in your code (line 1161):**
```go
return hex.EncodeToString(b)
```

**Conversion example:**
```
Random bytes: [167, 243, 184, 44, ...]
      ↓ hex.EncodeToString()
Hex string:   "a7f3b82c..."
```

**Why hex?**
- Compact representation of binary data
- URL-safe (only 0-9, a-f characters)
- Easy to copy/paste in emails

---

### 6. `encoding/json` - JSON Encoding/Decoding

**What it does:** Converts Go data structures to/from JSON

**Used in your code:**

**Encoding (Go → JSON):**
```go
// Line 905
json.NewEncoder(w).Encode(map[string]string{
    "status": "success",
    "message": "Place submitted for review",
})
```

**Output:**
```json
{
    "status": "success",
    "message": "Place submitted for review"
}
```

**Decoding (JSON → Go):**
```go
// Line 968
var req AIChatRequest
json.NewDecoder(r.Body).Decode(&req)
```

**How it works:**
1. Client sends: `{"prompt": "Find restaurants"}`
2. `Decode` fills the `AIChatRequest` struct
3. Now `req.Prompt` contains `"Find restaurants"`

**Struct tags (line 155):**
```go
type AIChatRequest struct {
    Prompt string `json:"prompt"`
}
```

The `` `json:"prompt"` `` tells the JSON encoder:
- Go field: `Prompt` (capitalized)
- JSON field: `"prompt"` (lowercase)

---

### 7. `fmt` - Formatted I/O

**What it does:** String formatting and printing (like printf in C)

**Used in your code:**

**String formatting (line 436):**
```go
verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
// Result: "http://localhost:8080/verify?token=a7f3b82c..."
```

**Error creation (line 335):**
```go
return User{}, fmt.Errorf("no valid session")
```

**Common format verbs:**
```go
fmt.Sprintf("%s", "text")     // String
fmt.Sprintf("%d", 42)         // Decimal integer
fmt.Sprintf("%f", 3.14)       // Float
fmt.Sprintf("%v", anything)   // Default format (any type)
```

**Your code uses `%s` for strings**, which is perfect for building URLs and messages.

---

### 8. `html/template` - HTML Template Engine

**What it does:** Safely generates HTML from templates

**Used in your code (lines 44, 206-213):**
```go
var tpl *template.Template  // Global template variable

tpl = template.Must(template.New("main").Funcs(template.FuncMap{
    "safeHTML": func(s string) template.HTML {
        return template.HTML(s)
    },
    "formatTime": func(t time.Time) string {
        return t.Format("Jan 2, 2006 at 3:04 PM")
    },
}).Parse(allTemplates))
```

**What this does:**
1. Creates a template system
2. Registers custom functions (`safeHTML`, `formatTime`)
3. Parses all HTML templates (the giant string starting at line 1172)

**Why templates?**
- **Security:** Auto-escapes user input to prevent XSS attacks
- **Reusability:** Define HTML once, use with different data
- **Separation:** Keep HTML separate from Go logic

**Example usage (line 1165):**
```go
func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
    tpl.ExecuteTemplate(w, tmplName, data)
}
```

We'll cover templates in depth in Chapter 9!

---

### 9. `log` - Logging

**What it does:** Logs messages to the console

**Used in your code:**

**Informational:**
```go
log.Println("Database initialized and tables created.")  // Line 195
log.Println("Starting server on " + baseURL + " ...")    // Line 220
```

**Fatal errors (stops program):**
```go
log.Fatal("Failed to initialize database:", err)  // Line 193
```

**Error logging (doesn't stop):**
```go
log.Printf("Failed to send verification email: %v", err)  // Line 440
```

**Output format:**
```
2024/01/15 10:30:45 Database initialized and tables created.
2024/01/15 10:30:45 Starting server on http://localhost:8080 ...
```

---

### 10. `net/http` - HTTP Server and Client

**What it does:** Complete HTTP implementation (server + client)

**This is the heart of your web application!**

**Used for:**

**1. Creating the server (line 221):**
```go
http.ListenAndServe(":8080", mux)
```

**2. Routing (line 229):**
```go
mux.HandleFunc("/", homeHandler)
```

**3. Handler functions:**
```go
func homeHandler(w http.ResponseWriter, r *http.Request) {
    // w = response writer (send data to client)
    // r = request (data from client)
}
```

**4. Making HTTP requests (line 1064):**
```go
resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
```

**Key types:**
- `http.Request` - Incoming request data
- `http.ResponseWriter` - Send response to client
- `http.ServeMux` - URL router
- `http.MethodGet`, `http.MethodPost` - HTTP method constants

---

### 11. `net/smtp` - Email Sending

**What it does:** Sends emails via SMTP protocol

**Used in your code (line 1150-1155):**
```go
func sendEmail(to, subject, body string) error {
    auth := smtp.PlainAuth("", smtpEmail, smtpPassword, smtpHost)
    msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, subject, body))
    addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
    return smtp.SendMail(addr, auth, smtpEmail, []string{to}, msg)
}
```

**How it works:**
```
Your App → SMTP Server (port 587) → Recipient's Email
```

**Used for:** Email verification (line 439)
```go
verificationLink := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
emailBody := fmt.Sprintf("Welcome %s!\n\nClick here to verify: %s", username, verificationLink)
sendEmail(email, "Verify Your Email", emailBody)
```

---

### 12. `strconv` - String Conversions

**What it does:** Converts strings to/from numbers

**Used in your code:**

**String to int (line 558):**
```go
userID, _ := strconv.Atoi(r.FormValue("user_id"))
// "42" → 42
```

**Float parsing (line 644):**
```go
lat, _ := strconv.ParseFloat(r.FormValue("latitude"), 64)
// "42.8" → 42.8
```

**Common functions:**
- `strconv.Atoi(s)` - String to int
- `strconv.Itoa(i)` - Int to string
- `strconv.ParseFloat(s, 64)` - String to float64
- `strconv.ParseBool(s)` - String to bool

---

### 13. `strings` - String Utilities

**What it does:** String manipulation functions

**Used in your code:**

**Splitting strings (line 806):**
```go
pathParts := strings.Split(r.URL.Path, "/")
// "/place/42" → ["", "place", "42"]
```

**Lowercase conversion (line 751, 1095):**
```go
searchParam := "%" + strings.ToLower(searchQuery) + "%"
lowerPrompt := strings.ToLower(prompt)
```

**Contains check (line 1100):**
```go
if strings.Contains(lowerPrompt, keyword) {
    return "counseling"
}
```

**Trimming whitespace (line 1083):**
```go
classification := strings.TrimSpace(strings.ToLower(text))
```

**Common functions:**
- `strings.Contains(s, substr)` - Check if substring exists
- `strings.Split(s, sep)` - Split into slice
- `strings.ToLower(s)` - Convert to lowercase
- `strings.TrimSpace(s)` - Remove leading/trailing spaces
- `strings.Join(slice, sep)` - Join slice into string

---

### 14. `time` - Date and Time

**What it does:** Time and duration operations

**Used in your code:**

**Getting current time (line 418):**
```go
expiry := time.Now().Add(24 * time.Hour)
// Current time + 24 hours
```

**Comparing times (line 509):**
```go
db.Exec("UPDATE users SET ... WHERE token_expiry > ?", time.Now())
```

**Type in structs (line 74, 100):**
```go
TokenExpiry sql.NullTime
CreatedAt   time.Time
```

**Formatting times (line 211):**
```go
"formatTime": func(t time.Time) string {
    return t.Format("Jan 2, 2006 at 3:04 PM")
}
```

**Go's unique date format:**
Instead of `YYYY-MM-DD`, Go uses a reference time:
```
Mon Jan 2 15:04:05 MST 2006
```

Examples:
- `"2006-01-02"` → `"2024-01-15"`
- `"Jan 2, 2006"` → `"Jan 15, 2024"`
- `"3:04 PM"` → `"10:30 AM"`

---

## External Dependencies

These must be installed with `go get`:

### 15. `github.com/gorilla/sessions` - Session Management

**What it does:** Manages user sessions (keeps users logged in)

**Installation:**
```bash
go get github.com/gorilla/sessions
```

**Used in your code (lines 198-203, throughout):**
```go
store = sessions.NewCookieStore([]byte(sessionKey))
store.Options = &sessions.Options{
    Path:     "/",
    MaxAge:   86400 * 7, // 7 days
    HttpOnly: true,
}
```

**How sessions work:**
```
1. User logs in successfully
2. Server creates session, stores user ID
3. Server sends cookie to browser
4. Browser includes cookie in future requests
5. Server reads cookie, knows user is logged in
```

**In your code (line 481-483):**
```go
session, _ := store.Get(r, "session")
session.Values["user_id"] = user.ID  // Store user ID in session
session.Save(r, w)                    // Send cookie to browser
```

**Reading session (line 332-336):**
```go
session, _ := store.Get(r, "session")
userID, ok := session.Values["user_id"].(int)
if !ok || userID == 0 {
    return User{}, fmt.Errorf("no valid session")
}
```

**Why Gorilla Sessions?**
- ✅ Secure cookie encryption
- ✅ Easy to use
- ✅ Widely trusted library

---

### 16. `github.com/mattn/go-sqlite3` - SQLite Driver

**What it does:** SQLite database driver for `database/sql`

**Installation:**
```bash
go get github.com/mattn/go-sqlite3
```

**The special import (line 20):**
```go
_ "github.com/mattn/go-sqlite3" // SQLite driver
```

**Why the underscore `_`?**
- You don't directly call functions from this package
- It registers itself with `database/sql` automatically
- The `_` says "import for side effects only"

**How it works:**
```go
// This line automatically uses the SQLite driver
db, err := sql.Open("sqlite3", filepath)
```

The string `"sqlite3"` tells `database/sql` to use the registered SQLite driver.

**SQLite advantages:**
- ✅ No separate database server needed
- ✅ Single file database (`users.db`)
- ✅ Perfect for small to medium apps
- ✅ Easy to backup (just copy the file)

---

### 17. `golang.org/x/crypto/bcrypt` - Password Hashing

**What it does:** Securely hashes and verifies passwords

**Installation:**
```bash
go get golang.org/x/crypto/bcrypt
```

**Used in your code:**

**Hashing a password (line 405, 321):**
```go
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

**Verifying a password (line 470):**
```go
err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
if err != nil {
    // Wrong password!
}
```

**Why bcrypt?**
- ✅ **Slow by design** - Makes brute force attacks impractical
- ✅ **Salted automatically** - Each hash is unique
- ✅ **Adaptive** - Can increase difficulty as computers get faster

**Example:**
```
Password: "mypassword123"
    ↓ bcrypt.GenerateFromPassword()
Hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
```

**NEVER store plain passwords!** Always use bcrypt or similar.

---

## Managing Dependencies

### The `go.mod` File

Your project should have a `go.mod` file listing dependencies:

```
module yourproject

go 1.21

require (
    github.com/gorilla/sessions v1.2.1
    github.com/mattn/go-sqlite3 v1.14.18
    golang.org/x/crypto v0.16.0
)
```

### Installing Dependencies

```bash
# Install all dependencies listed in go.mod
go mod download

# Or just build (auto-downloads dependencies)
go build main.go
```

### Adding New Dependencies

```bash
# Download and add to go.mod
go get github.com/some/package

# Update all dependencies
go get -u ./...
```

---

## Import Best Practices

### 1. Grouping

Your code follows Go convention:
```go
import (
    // Standard library (alphabetical)
    "bytes"
    "context"
    // ...

    // External packages (alphabetical)
    "github.com/gorilla/sessions"
    // ...
)
```

### 2. Unused Imports

Go **won't compile** if you import something you don't use!

```go
import "fmt"  // Error if never used
```

Exception: The `_` blank import for side effects

### 3. Import Aliases

You can rename imports:
```go
import (
    cryptorand "crypto/rand"  // Alias to avoid conflict
    mathrand "math/rand"
)
```

---

## Practice Exercise

Match each package to its use in your code:

| Package | What does it do in your app? |
|---------|------------------------------|
| `net/http` | ? |
| `database/sql` | ? |
| `bcrypt` | ? |
| `sessions` | ? |
| `encoding/json` | ? |

**Answers:**
1. `net/http` - Runs the web server and handles HTTP requests
2. `database/sql` - Queries and updates the SQLite database
3. `bcrypt` - Hashes passwords securely
4. `sessions` - Keeps users logged in across requests
5. `encoding/json` - Sends JSON responses to AJAX requests

---

## Dependency Graph

```
Your main.go
    ├── net/http (Standard Lib)
    │   └── Provides web server
    │
    ├── database/sql (Standard Lib)
    │   └── go-sqlite3 (External)
    │       └── Enables SQLite
    │
    ├── gorilla/sessions (External)
    │   └── Provides session management
    │
    ├── bcrypt (External)
    │   └── Hashes passwords
    │
    └── encoding/json (Standard Lib)
        └── Handles JSON APIs
```

---

## Key Takeaways

✅ **Standard library** - Comes with Go, no installation needed
✅ **External dependencies** - Require `go get` to install
✅ **Import grouping** - Standard lib first, then external
✅ **Blank imports** (`_`) - Used for side effects (like database drivers)
✅ **`go.mod`** - Tracks your dependencies and versions

**Your app uses 17 imports** - 14 from standard library, 3 external. This is a healthy ratio! Many projects try to minimize external dependencies.

---

**Next Chapter:** We'll dive deep into structs and data models, understanding how your app organizes data!
