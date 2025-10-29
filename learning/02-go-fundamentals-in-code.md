# Chapter 2: Go Fundamentals in Your Code

## Introduction

You mentioned you know variables, functions, and basic syntax. Excellent! This chapter will show you how those fundamentals are used in your specific code, plus introduce some intermediate concepts you'll encounter.

---

## 1. Package Declaration (Line 1)

```go
package main
```

**What it means:**
- Every Go file belongs to a **package**
- `package main` is special - it tells Go this is an executable program
- Other packages (like `package utils`) would be libraries

**Why it matters:**
- Only `package main` can have a `main()` function
- Only `package main` creates a runnable program
- Libraries use different package names

---

## 2. Constants (Lines 25-38)

### Basic Constants

```go
const (
    smtpHost     = "mail.needgreatersglobal.com"
    smtpPort     = "587"
    smtpEmail    = "endrig@needgreatersglobal.com"
    smtpPassword = "Assembly3637997Ab,"
    sessionKey   = "a-very-secret-key-32-bytes-long"
    baseURL      = "http://localhost:8080"
    geminiAPIKey = "AIzaSyD6NfOys90qNnnV597M_u_ePTnR1k-8r1w"
    geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
)
```

**What you need to know:**

**Constants** are values that NEVER change during program execution.

**Grouped Declaration:**
- The `const ( )` syntax declares multiple constants at once
- No commas needed between declarations (unlike some languages)

**Type Inference:**
- Go figures out the types automatically:
  - `smtpPort` is a `string`
  - If you wrote `const maxUsers = 100`, it would be an `int`

**Why use constants?**
- ✅ Compiler enforces they can't change
- ✅ No memory allocation overhead
- ✅ Easy to find and update configuration

**Bad practice alert:** Putting passwords directly in code is insecure! You should use environment variables instead. We'll cover this in Chapter 12 (Security).

### Multi-line String Constants (Lines 48-61)

```go
const aiSystemPrompt = `
You are a simple classification bot for a consulting website.
Your ONLY job is to read the user's prompt and classify their intent.
...
`
```

**The backtick syntax:**
- `` `...` `` creates a **raw string literal**
- Can span multiple lines
- Preserves formatting (spaces, newlines)
- Doesn't need escape characters like `\n`

**Compare:**
```go
// With double quotes (need escapes)
const msg = "Line 1\nLine 2\nLine 3"

// With backticks (natural formatting)
const msg = `Line 1
Line 2
Line 3`
```

---

## 3. Variables and the `var` Keyword

### Global Variables (Lines 41-45)

```go
var (
    db    *sql.DB               // Database connection pool
    store *sessions.CookieStore // Session store
    tpl   *template.Template    // HTML templates
)
```

**What's happening here:**

**Grouped variable declaration:**
- Similar to constants, but these CAN change
- Declared at package level (outside any function)
- Accessible by all functions in the file

**The asterisk `*`:**
- `*sql.DB` means "a pointer to a sql.DB"
- **Pointers** store memory addresses, not actual values
- We'll explore pointers more in a moment

**Initial values:**
- These variables start as `nil` (Go's version of null)
- They get actual values in the `main` function (lines 191-213)

### Local Variables

Throughout your code, you'll see different ways to declare variables:

#### Method 1: Standard Declaration

```go
var err error  // Declare with type
var count int
```

#### Method 2: Declaration with Initialization

```go
var message string = "Hello"
var users []User   // Slice of User structs
```

#### Method 3: Short Declaration (Most Common)

```go
username := r.FormValue("username")  // Type inferred automatically
places := []Place{}                  // Empty slice
```

**The `:=` operator:**
- Only works INSIDE functions (not at package level)
- Automatically determines the type
- Very common in Go code

**Example from your code (line 188):**
```go
var err error  // Declared outside, used multiple times
```

**Example from your code (line 400):**
```go
username := r.FormValue("username")  // Short declaration
```

---

## 4. Types in Go

### Basic Types Used in Your Code

```go
string                  // Text: "hello"
int                     // Whole numbers: 42, -10
float64                 // Decimals: 42.8, -3.14
bool                    // true or false
time.Time               // Dates/times
```

### Composite Types

#### Slices (Dynamic Arrays)

```go
// From line 608
var users []User  // Slice of User structs
```

**What is a slice?**
- Like an array, but can grow/shrink
- Most common collection type in Go
- Zero value is `nil`

**Common operations:**
```go
// Create empty slice
places := []Place{}

// Append items
places = append(places, newPlace)

// Loop through
for i, place := range places {
    fmt.Println(i, place.Title)
}

// Get length
count := len(places)
```

#### Maps (Key-Value Pairs)

```go
// Example: map[string]string means "keys are strings, values are strings"
data := map[string]string{
    "status": "success",
    "message": "Place submitted",
}
```

**In your code (line 905):**
```go
json.NewEncoder(w).Encode(map[string]string{
    "status": "success",
    "message": "Place submitted for review",
})
```

This creates a temporary map and encodes it as JSON.

---

## 5. Pointers (The `*` and `&` Symbols)

Pointers are one of Go's most important concepts. Let's demystify them!

### What is a Pointer?

A pointer stores a **memory address** instead of a value.

```go
var x int = 42        // Normal variable
var p *int = &x       // Pointer to x's memory address
```

### In Your Code

#### Example 1: Database Connection (Line 42)

```go
var db *sql.DB  // Pointer to a sql.DB object
```

**Why a pointer?**
- The actual database connection is large and complex
- Passing a pointer is efficient (just an address)
- Multiple functions can share the same connection

#### Example 2: Passing Pointers to Functions (Line 191)

```go
db, err = initDB("./users.db")
```

The `initDB` function returns `*sql.DB` (a pointer). This means:
- Only one database connection exists in memory
- All handlers use the same connection
- Very efficient!

### The `&` Operator (Address-of)

Gets the memory address of a variable.

**Example from your code (line 198):**
```go
store = sessions.NewCookieStore([]byte(sessionKey))
```

If we wanted a pointer to `store`:
```go
storePointer := &store  // storePointer is type **sessions.CookieStore
```

### When to Use Pointers?

**In your code, pointers are used for:**
1. **Large structs** - Avoid copying entire objects
2. **Shared resources** - Database connections, templates
3. **Modifying function parameters** - Change original values

**You DON'T need to think about pointers for:**
- Basic types (int, string, bool) - Go handles this efficiently
- Most function calls - Go makes it intuitive

---

## 6. Structs (Custom Types)

Structs are like objects in other languages - they group related data.

### Example: User Struct (Lines 66-75)

```go
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
```

**Breakdown:**

**`type User struct`**
- Creates a new type named `User`
- It's a struct (collection of fields)

**Fields:**
- Each field has a name and a type
- Similar to a class with properties in other languages

**Special types:**
- `sql.NullString` - A string that can be NULL in the database
- `sql.NullTime` - A time that can be NULL
- Regular `string` can't be NULL, so we need these special types

### Creating and Using Structs

```go
// Method 1: Zero values
var user User  // All fields are zero/empty

// Method 2: Literal initialization
user := User{
    ID:       1,
    Username: "john",
    Email:    "john@example.com",
}

// Method 3: Partial initialization (others are zero)
user := User{Username: "jane"}

// Accessing fields
fmt.Println(user.Username)  // "jane"
user.IsVerified = true       // Modify field
```

### Structs in Your Code

**Example from line 464:**
```go
var user User  // Create empty User struct
err := db.QueryRow(...).Scan(&user.ID, &user.Username, ...)
```

**What's happening:**
1. Create empty `User` struct
2. Query database for user data
3. `Scan` fills the struct fields with database values
4. Now `user` contains the full user data

---

## 7. Functions

### Basic Function Anatomy

```go
func functionName(parameter type) returnType {
    // function body
    return value
}
```

### Example from Your Code (Line 1158)

```go
func generateToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return hex.EncodeToString(b)
}
```

**Breakdown:**
- **`func`** - Keyword to define a function
- **`generateToken`** - Function name
- **`()`** - No parameters
- **`string`** - Returns a string
- **`return hex.EncodeToString(b)`** - Returns the value

### Multiple Return Values

Go functions can return multiple values! Very common pattern:

```go
func initDB(filepath string) (*sql.DB, error) {
    // ...
    return db, err  // Returns both database AND error
}
```

**Using multiple returns (line 191):**
```go
db, err = initDB("./users.db")
if err != nil {
    log.Fatal("Failed to initialize database:", err)
}
```

**The pattern:**
- First return value: the result you want
- Second return value: an error (or `nil` if no error)
- **ALWAYS check if `err != nil`** before using the first value

### Functions as Parameters

**Example from your code (line 246):**
```go
mux.HandleFunc("/api/comment", requireAuth(commentHandler))
```

**What's happening:**
- `commentHandler` is a function
- `requireAuth` takes a function, wraps it, returns a new function
- This is called **middleware** (we'll cover in Chapter 8)

---

## 8. Error Handling

Go doesn't have try/catch. Instead, it uses explicit error checking.

### The Standard Pattern

```go
result, err := someFunction()
if err != nil {
    // Handle the error
    log.Fatal(err)
    return
}
// Continue if no error
```

### Example from Your Code (Lines 192-194)

```go
db, err = initDB("./users.db")
if err != nil {
    log.Fatal("Failed to initialize database:", err)
}
```

**What this does:**
1. Call `initDB`
2. If it returns an error, log it and exit the program
3. If no error, continue with the database connection

### Different Error Handling Strategies

**1. Fatal error (stop the program):**
```go
if err != nil {
    log.Fatal(err)  // Logs error and exits
}
```

**2. Return the error to caller:**
```go
if err != nil {
    return nil, err  // Let caller decide what to do
}
```

**3. Handle gracefully:**
```go
if err != nil {
    http.Error(w, "Database error", http.StatusInternalServerError)
    return
}
```

### Ignoring Errors with `_`

Sometimes you don't care about an error:

```go
rowsAffected, _ := result.RowsAffected()  // Ignore error
```

**Use carefully!** Usually better to check errors.

---

## 9. Control Flow

### If Statements

```go
// Simple if
if condition {
    // do something
}

// If with initialization (common pattern)
if value := getValue(); value > 10 {
    // value only exists in this block
}

// If-else
if condition {
    // true branch
} else {
    // false branch
}
```

**Example from your code (line 391):**
```go
if r.Method == http.MethodGet {
    // Handle GET request
    return
}
// Handle POST request (implied else)
```

### For Loops

Go only has `for` loops (no `while`):

```go
// Standard loop
for i := 0; i < 10; i++ {
    fmt.Println(i)
}

// While-style loop
for condition {
    // Keep going while condition is true
}

// Infinite loop
for {
    // Forever (until break)
}

// Range loop (very common)
for index, value := range slice {
    fmt.Println(index, value)
}
```

**Example from your code (line 609):**
```go
for rows.Next() {
    var u User
    rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
    users = append(users, u)
}
```

**What this does:**
- `rows.Next()` returns true while there are more database rows
- Each iteration processes one row
- Appends the user to the slice

### Switch Statements

**Example from your code (line 562):**
```go
switch action {
case "toggle_admin":
    // Handle toggle
case "delete":
    // Handle delete
}
```

Cleaner than multiple if-else statements!

---

## 10. The `defer` Keyword

`defer` delays a function call until the surrounding function returns.

**Example from your code (line 606):**
```go
rows, err := db.Query("SELECT ...")
if err != nil {
    // handle error
}
defer rows.Close()  // Will close when function returns
```

**Why this is brilliant:**
- You declare cleanup right next to resource acquisition
- No matter how the function exits (return, panic, etc.), it will close
- Prevents resource leaks

**Common uses:**
```go
defer file.Close()           // Close files
defer rows.Close()           // Close database results
defer session.Save(r, w)     // Save sessions
```

---

## 11. Nil - Go's "Null"

`nil` represents the zero value for pointers, slices, maps, channels, and interfaces.

**Examples:**

```go
var db *sql.DB          // db is nil
var users []User        // users is nil (not the same as empty slice!)
var data map[string]int // data is nil

// Checking for nil
if db == nil {
    // Database not initialized
}

// Safe pattern
if err != nil {
    // Error occurred
}
```

**In your code (line 334):**
```go
if !ok || userID == 0 {
    return User{}, fmt.Errorf("no valid session")
}
```

---

## 12. Type Assertions and Conversions

### Type Assertion (Line 542)

```go
user := r.Context().Value("user").(User)
```

**What's happening:**
- `r.Context().Value("user")` returns `interface{}` (any type)
- `.(User)` asserts "this is actually a User"
- If wrong type, program panics

**Safe version:**
```go
user, ok := r.Context().Value("user").(User)
if !ok {
    // Not a User!
}
```

### Type Conversion (Line 558)

```go
userID, _ := strconv.Atoi(r.FormValue("user_id"))
```

**`strconv.Atoi`** converts string to int:
- "42" → 42
- "abc" → 0 (and error)

---

## Practice Exercises

Try to understand these snippets from your code:

### Exercise 1 (Lines 400-402)
```go
username := r.FormValue("username")
email := r.FormValue("email")
password := r.FormValue("password")
```

**Questions:**
1. What operator is used? `:=`
2. What's the type of `username`? `string`
3. Where do these values come from? Form submitted by user

### Exercise 2 (Lines 608-612)
```go
var users []User
for rows.Next() {
    var u User
    rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
    users = append(users, u)
}
```

**Questions:**
1. What type is `users`? Slice of User structs
2. What does `append` do? Adds `u` to the end of the slice
3. Why use `&u.ID` in Scan? Pass pointer so Scan can modify the value

### Exercise 3 (Lines 464-468)
```go
var user User
err := db.QueryRow("SELECT ... WHERE username = ?", username, username).
    Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash,
         &user.IsVerified, &user.IsAdmin)

if err != nil || bcrypt.CompareHashAndPassword(...) != nil {
    // Invalid login
}
```

**Questions:**
1. What happens if database query fails? `err != nil` is true
2. What does `Scan` do? Fills user struct fields with database values
3. Why check `err != nil`? Could be no matching user, database error, etc.

---

## Key Takeaways

✅ **Constants** - Use for config values that never change
✅ **Variables** - Use `:=` for local variables, `var` for package-level
✅ **Pointers** - Used for efficiency and shared resources
✅ **Structs** - Group related data (like User, Place)
✅ **Functions** - Can return multiple values, especially `(result, error)`
✅ **Error Handling** - Always check `if err != nil`
✅ **defer** - Ensures cleanup happens
✅ **nil** - The zero value for reference types

---

**Next Chapter:** We'll explore the imports at the top of your file and understand what each external package does!
