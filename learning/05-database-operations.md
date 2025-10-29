# Chapter 5: Database Operations

## Introduction

Your application uses **SQLite** - a lightweight, file-based database. This chapter explains how data is stored, queried, and updated. You'll understand every database operation in your code!

---

## Database Overview

**File:** `users.db` (created automatically)

**Tables:**
1. **users** - User accounts
2. **places** - Location submissions
3. **comments** - Place comments

**Relationships:**
```
users (1) ──→ (many) places
  └─ A user can submit many places

users (1) ──→ (many) comments
  └─ A user can write many comments

places (1) ──→ (many) comments
  └─ A place can have many comments
```

---

## Section 1: Database Initialization (Lines 257-328)

### The initDB Function

```go
func initDB(filepath string) (*sql.DB, error) {
    db, err := sql.Open("sqlite3", filepath)
    if err != nil {
        return nil, err
    }

    // Test the connection
    if err = db.Ping(); err != nil {
        return nil, err
    }

    // Create tables...
}
```

**Step-by-step:**

1. **sql.Open()** - Opens database connection
   ```go
   db, err := sql.Open("sqlite3", "./users.db")
   ```
   - `"sqlite3"` - Driver name (registered by go-sqlite3 package)
   - `"./users.db"` - File path (creates if doesn't exist)

2. **db.Ping()** - Verify connection works
   ```go
   if err = db.Ping(); err != nil {
       return nil, err
   }
   ```
   - Actually connects to database
   - `sql.Open` is lazy (doesn't connect immediately)

3. **Create tables** - Define schema

---

### Table Schemas

#### Users Table (Lines 269-279)

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    verification_token TEXT,
    token_expiry DATETIME
);
```

**Field explanations:**

| Field | Type | Constraints | Purpose |
|-------|------|-------------|---------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier, auto-generates 1, 2, 3... |
| `username` | TEXT | UNIQUE, NOT NULL | Must be unique, cannot be NULL |
| `email` | TEXT | UNIQUE, NOT NULL | Must be unique, cannot be NULL |
| `password_hash` | TEXT | NOT NULL | Bcrypt hash of password |
| `is_verified` | BOOLEAN | DEFAULT FALSE | Starts as false until email verified |
| `is_admin` | BOOLEAN | DEFAULT FALSE | Regular users are false |
| `verification_token` | TEXT | (nullable) | Random token for email verification |
| `token_expiry` | DATETIME | (nullable) | When token expires |

**Why AUTOINCREMENT?**
```
Insert user 1 → id = 1
Insert user 2 → id = 2
Delete user 1
Insert user 3 → id = 3  (NOT 1, keeps incrementing)
```

#### Places Table (Lines 281-295)

```sql
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
);
```

**New concepts:**

**REAL** - Floating point number (for coordinates)
```
latitude: 42.6026
longitude: 20.9030
```

**DEFAULT CURRENT_TIMESTAMP** - Automatically sets to current time
```go
// You don't need to set created_at when inserting
db.Exec("INSERT INTO places (title, ...) VALUES (?, ...)", title, ...)
// created_at is set automatically!
```

**FOREIGN KEY** - Links to another table
```sql
FOREIGN KEY(submitted_by_user_id) REFERENCES users(id)
```

This means:
- `submitted_by_user_id` must match an existing `users.id`
- Can't insert a place with `submitted_by_user_id = 999` if user 999 doesn't exist

#### Comments Table (Lines 296-306)

```sql
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    place_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(place_id) REFERENCES places(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

**ON DELETE CASCADE** - Important!
```
If place 42 is deleted:
  → All comments with place_id = 42 are also deleted
```

Without CASCADE:
```
Try to delete place 42
  → Error! Comments reference it
  → Must delete comments first
```

With CASCADE:
```
Delete place 42
  → SQLite automatically deletes all related comments
  → Clean deletion!
```

---

### Creating a Default Admin User (Lines 317-325)

```go
var count int
db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
if count == 0 {
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
    db.Exec("INSERT INTO users (username, email, password_hash, is_verified, is_admin) VALUES (?, ?, ?, ?, ?)",
        "admin", "admin@example.com", string(hashedPassword), true, true)
    log.Println("Created default admin user: admin/admin123")
}
```

**Why check count first?**
- Prevents duplicate admin creation
- Safe to restart the app multiple times

**Flow:**
```
App starts for first time:
  → Count = 0
  → Create admin user
  → Log: "Created default admin user"

App restarts:
  → Count = 1 (admin exists)
  → Skip creation
```

---

## Section 2: CRUD Operations

CRUD = **C**reate, **R**ead, **U**pdate, **D**elete

### Create (INSERT)

#### Example 1: User Registration (Lines 421-424)

```go
_, err = db.Exec(
    "INSERT INTO users (username, email, password_hash, verification_token, token_expiry) VALUES (?, ?, ?, ?, ?)",
    username, email, string(hashedPassword), token, expiry,
)
```

**Breakdown:**

**db.Exec()** - Executes a query that modifies data
```go
result, err := db.Exec(query, args...)
```

**Placeholders `?`** - Prevents SQL injection
```go
// ❌ UNSAFE (SQL injection vulnerability)
query := "INSERT INTO users (username) VALUES ('" + username + "')"

// ✅ SAFE (uses placeholders)
db.Exec("INSERT INTO users (username) VALUES (?)", username)
```

**If username = `"admin'; DROP TABLE users;--"`:
- Unsafe version: Deletes your entire users table! 💀
- Safe version: Stores the string as-is ✅

**Ignoring result with `_`:**
```go
_, err = db.Exec(...)
```
- We don't need the result (only checking for errors)
- Could use result to get last inserted ID or rows affected

#### Example 2: Submitting a Place (Lines 891-895)

```go
_, err = db.Exec(`
    INSERT INTO places (title, description, category, latitude, longitude, google_maps_link,
                       submitted_by_user_id, is_approved)
    VALUES (?, ?, ?, 0, 0, ?, ?, FALSE)`,
    title, description, category, googleMapsLink, user.ID)
```

**Multi-line query** - Uses backticks for readability

**Mixing literals and placeholders:**
- `0, 0` - Literal zeros for coordinates (admin sets later)
- `FALSE` - Literal boolean (needs approval)
- `?` - User-provided values (safe from injection)

---

### Read (SELECT)

#### Example 1: Single Row (Lines 465-468)

```go
var user User
err := db.QueryRow(
    "SELECT id, username, email, password_hash, is_verified, is_admin FROM users WHERE username = ? OR email = ?",
    username, username,
).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsAdmin)
```

**QueryRow** - Expects exactly one row (or error)

**Scan** - Fills variables with column values
```
Database row:     [42, "john", "john@example.com", "$2a$10...", true, false]
                   ↓    ↓      ↓                    ↓          ↓       ↓
Scan parameters: &user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsAdmin
                   ↓
User struct:      {ID: 42, Username: "john", Email: "john@example.com", ...}
```

**Why `&` (address-of)?**
- Scan needs to modify the variables
- Passing a pointer allows Scan to write to them

**Error handling:**
```go
if err != nil {
    // Could be:
    // - No matching user (sql.ErrNoRows)
    // - Database connection error
    // - Query syntax error
}
```

#### Example 2: Multiple Rows (Lines 685-704)

```go
rows, err := db.Query(`
    SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
           p.google_maps_link, p.created_at, u.username
    FROM places p
    JOIN users u ON p.submitted_by_user_id = u.id
    WHERE p.is_approved = FALSE
    ORDER BY p.created_at DESC
`)
if err != nil {
    http.Error(w, "Database error", http.StatusInternalServerError)
    return
}
defer rows.Close()

var pendingPlaces []Place
for rows.Next() {
    var p Place
    rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
        &p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername)
    pendingPlaces = append(pendingPlaces, p)
}
```

**Query** - Returns multiple rows

**JOIN** - Combines data from two tables
```sql
FROM places p
JOIN users u ON p.submitted_by_user_id = u.id
```

**Visualization:**
```
places table:          users table:
┌────┬───────┬────────┐  ┌────┬──────────┐
│ id │ title │ user_id│  │ id │ username │
├────┼───────┼────────┤  ├────┼──────────┤
│ 1  │ "Cafe"│   5    │  │ 5  │ "john"   │
│ 2  │ "Park"│   7    │  │ 7  │ "jane"   │
└────┴───────┴────────┘  └────┴──────────┘

After JOIN:
┌────┬───────┬────────┬──────────┐
│ id │ title │ user_id│ username │
├────┼───────┼────────┼──────────┤
│ 1  │ "Cafe"│   5    │ "john"   │
│ 2  │ "Park"│   7    │ "jane"   │
└────┴───────┴────────┴──────────┘
```

**rows.Next()** - Advances to next row
```go
for rows.Next() {  // true while rows remain
    // Process row
}
```

**defer rows.Close()** - CRITICAL!
- Closes database resources when function returns
- Prevents connection leaks
- Always use defer right after Query()

#### Example 3: Subquery (Lines 740-742)

```go
query := `
    SELECT p.id, p.title, ...,
           (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
    FROM places p
    ...
`
```

**Subquery** - Query inside a query

**For each place:**
```sql
(SELECT COUNT(*) FROM comments WHERE place_id = p.id)
```

Returns the count of comments for that place.

**Result:**
```
place_id | title      | comment_count
---------+------------+--------------
1        | "Cafe"     | 5
2        | "Park"     | 0
3        | "Museum"   | 12
```

---

### Update (UPDATE)

#### Example 1: Verify Email (Lines 507-510)

```go
result, err := db.Exec(
    "UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = ? AND token_expiry > ?",
    token, time.Now(),
)
```

**Multiple SET clauses:**
```sql
UPDATE users
SET is_verified = TRUE,     -- Set verified
    verification_token = NULL -- Clear token
WHERE verification_token = ? AND token_expiry > ?
```

**WHERE conditions:**
- Token must match
- Token must not be expired

**Checking rows affected:**
```go
rowsAffected, _ := result.RowsAffected()
if rowsAffected == 0 {
    // No user found with that token
    // (invalid or expired)
}
```

#### Example 2: Approve Place (Lines 647-648)

```go
_, err := db.Exec("UPDATE places SET is_approved = TRUE, latitude = ?, longitude = ? WHERE id = ?",
    lat, lng, placeID)
```

**Sets:**
- `is_approved = TRUE` - Allow place to show on map
- `latitude = ?` - Admin-provided coordinate
- `longitude = ?` - Admin-provided coordinate

---

### Delete (DELETE)

#### Example 1: Delete User (Line 571)

```go
_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
```

**Simple deletion** - Remove by ID

#### Example 2: Delete Place (Line 655)

```go
_, err := db.Exec("DELETE FROM places WHERE id = ?", placeID)
```

**Cascading effect:**
- Because comments table has `ON DELETE CASCADE`
- Deleting a place also deletes all its comments
- Automatic cleanup!

---

## Section 3: Advanced Queries

### Filtering with LIKE (Lines 750-752)

```go
if searchQuery != "" {
    query += " AND (LOWER(p.title) LIKE ? OR LOWER(p.description) LIKE ?)"
    searchParam := "%" + strings.ToLower(searchQuery) + "%"
    args = append(args, searchParam, searchParam)
}
```

**LIKE operator** - Pattern matching

**Wildcards:**
- `%` - Matches any characters
- `_` - Matches single character

**Examples:**
```sql
LIKE '%pizza%'    -- Matches "Pizza Place", "Best pizza", "pizza"
LIKE 'pizza%'     -- Matches "pizza", "pizzeria" (starts with)
LIKE '%pizza'     -- Matches "pizza", "delicious pizza" (ends with)
LIKE 'p_zza'      -- Matches "pizza", "pozza" (single char wildcard)
```

**Your code:**
```go
searchParam := "%" + strings.ToLower(searchQuery) + "%"
// If searchQuery = "restaurant"
// searchParam = "%restaurant%"
// Matches: "Best Restaurant", "restaurant downtown", "My favorite restaurant"
```

**LOWER()** - Case-insensitive search
```sql
LOWER(p.title) LIKE ?
-- "PIZZA" and "pizza" both match "%pizza%"
```

### Dynamic Query Building (Lines 738-762)

```go
query := `SELECT ... FROM places p WHERE p.is_approved = TRUE`
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

rows, err := db.Query(query, args...)
```

**Why dynamic?**
User can filter by:
- Nothing: `SELECT ... WHERE is_approved = TRUE`
- Search: `SELECT ... WHERE is_approved = TRUE AND title LIKE '%pizza%'`
- Category: `SELECT ... WHERE is_approved = TRUE AND category = 'Restaurant'`
- Both: `SELECT ... WHERE is_approved = TRUE AND title LIKE '%pizza%' AND category = 'Restaurant'`

**args slice:**
```go
var args []interface{}  // Empty slice, can hold any types
args = append(args, value1)
args = append(args, value2)
// args = [value1, value2]

db.Query(query, args...)  // ... unpacks slice into separate parameters
```

---

## Section 4: Connection Pooling

### What is `*sql.DB`?

It's NOT a single connection—it's a **pool** of connections!

```
Your App
  ↓ db.Query()
Connection Pool (sql.DB)
  ├── Connection 1 [in use]
  ├── Connection 2 [in use]
  ├── Connection 3 [idle]
  └── Connection 4 [idle]
  ↓
SQLite Database File
```

**Automatic management:**
- Request comes in → Take idle connection
- Request finishes → Return connection to pool
- Too many requests → Create new connection
- Idle too long → Close connection

**Configuration (not in your code, but possible):**
```go
db.SetMaxOpenConns(25)      // Max 25 concurrent connections
db.SetMaxIdleConns(5)       // Keep 5 idle connections
db.SetConnMaxLifetime(5*time.Minute)  // Close after 5 minutes
```

---

## Section 5: Transactions (Not Used in Your Code)

Transactions ensure **all-or-nothing** operations.

**Example scenario:**
```
Transfer money:
1. Subtract $100 from Account A
2. Add $100 to Account B
```

**Without transaction:**
```
1. Subtract $100 from Account A ✅
2. [CRASH]
3. Add $100 to Account B ❌
Result: $100 disappeared!
```

**With transaction:**
```go
tx, _ := db.Begin()

tx.Exec("UPDATE accounts SET balance = balance - 100 WHERE id = ?", accountA)
tx.Exec("UPDATE accounts SET balance = balance + 100 WHERE id = ?", accountB)

err := tx.Commit()  // Both succeed or both fail
```

**Your code doesn't need transactions** because:
- Most operations are single queries
- No multi-step critical operations
- SQLite handles concurrency well for simple cases

---

## Section 6: Best Practices in Your Code

### ✅ Good Practices You're Using

1. **Placeholders instead of string concatenation**
   ```go
   // ✅ Safe
   db.Exec("SELECT * FROM users WHERE id = ?", userID)

   // ❌ Vulnerable to SQL injection
   db.Exec("SELECT * FROM users WHERE id = " + userID)
   ```

2. **defer rows.Close()**
   ```go
   rows, err := db.Query(...)
   defer rows.Close()  // Always clean up
   ```

3. **Error checking**
   ```go
   if err != nil {
       // Handle error
   }
   ```

4. **Foreign keys for data integrity**
   ```sql
   FOREIGN KEY(submitted_by_user_id) REFERENCES users(id)
   ```

### ⚠️ Areas for Improvement

1. **Connection pooling not configured**
   ```go
   // Add after db.Ping()
   db.SetMaxOpenConns(10)
   db.SetMaxIdleConns(5)
   ```

2. **Magic strings for queries**
   ```go
   // Could use constants
   const (
       queryGetUser = "SELECT id, username, ... FROM users WHERE id = ?"
       queryInsertPlace = "INSERT INTO places ..."
   )
   ```

3. **No database migrations**
   - Schema changes require manual updates
   - Consider tools like `golang-migrate`

---

## Common Pitfalls and Solutions

### Pitfall 1: Forgetting to Close Rows

```go
// ❌ Resource leak
rows, _ := db.Query(...)
for rows.Next() {
    // Process rows
}
// rows never closed!

// ✅ Always defer
rows, _ := db.Query(...)
defer rows.Close()
for rows.Next() {
    // Process rows
}
```

### Pitfall 2: Wrong Number of Scan Arguments

```go
// Query returns 3 columns
rows.Scan(&col1, &col2)  // ❌ Error: expected 3, got 2

rows.Scan(&col1, &col2, &col3)  // ✅ Correct
```

### Pitfall 3: Reusing Variable Names

```go
// ❌ Shadows err
user, err := getUser()
place, err := getPlace()  // err reassigned, lost previous error!

// ✅ Check err between calls
user, err := getUser()
if err != nil {
    return err
}
place, err := getPlace()
if err != nil {
    return err
}
```

---

## Practice Exercises

### Exercise 1: Write a Query

Get all places in the "Restaurant" category submitted by user ID 5:

**Solution:**
```go
rows, err := db.Query(`
    SELECT id, title, description
    FROM places
    WHERE category = ? AND submitted_by_user_id = ? AND is_approved = TRUE`,
    "Restaurant", 5)
```

### Exercise 2: Count Query

Count how many verified users exist:

**Solution:**
```go
var count int
err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_verified = TRUE").Scan(&count)
```

### Exercise 3: Update Query

Mark a user as an admin:

**Solution:**
```go
_, err := db.Exec("UPDATE users SET is_admin = TRUE WHERE id = ?", userID)
```

---

## Key Takeaways

✅ **db.Exec()** - INSERT, UPDATE, DELETE
✅ **db.QueryRow()** - SELECT single row
✅ **db.Query()** - SELECT multiple rows
✅ **Placeholders `?`** - Prevent SQL injection
✅ **Scan()** - Fill variables with row data
✅ **defer rows.Close()** - Always clean up
✅ **Foreign keys** - Maintain data relationships
✅ **JOIN** - Combine data from multiple tables

---

**Next Chapter:** HTTP routing and handlers - how URLs map to your Go functions!
