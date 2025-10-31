# Chapter 5: Database Operations 💾

## Welcome to the Database World!

Your app uses **SQLite** - a lightweight, file-based database. The entire database is just one file: `users.db`

**No separate database server needed!** Perfect for small-to-medium applications.

---

## 📍 Where Database Code Lives

**Database initialization:** Lines 281-378
**CRUD operations:** Throughout your handlers (Lines 380-1150)

**What you have:**
- 3 tables: `users`, `places`, `comments`
- 1 connection pool: `var db *sql.DB` (Line 42)
- Full CRUD: Create, Read, Update, Delete

---

## 🎯 What is a Database?

Think of a database as an organized filing cabinet:

```
Filing Cabinet (Database: users.db)
├── Drawer 1: users table
│   ├── Folder: User 1 (id=1, username="admin", ...)
│   ├── Folder: User 2 (id=2, username="john_doe", ...)
│   └── Folder: User 3 (id=3, username="jane", ...)
│
├── Drawer 2: places table
│   ├── Folder: Place 1 (id=1, title="Prizren Castle", ...)
│   └── Folder: Place 2 (id=2, title="Rugova Canyon", ...)
│
└── Drawer 3: comments table
    ├── Folder: Comment 1 (id=1, place_id=1, content="Amazing!", ...)
    └── Folder: Comment 2 (id=2, place_id=1, content="Must visit!", ...)
```

---

## 🚀 Database Initialization (Lines 281-378)

### Opening the Database (Lines 281-296)

```go
func initDB(filepath string) (*sql.DB, error) {
	// Open connection to database file
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}

	// Test that it actually works
	if err = db.Ping(); err != nil {
		return nil, err
	}

	// Create tables...
	return db, nil
}
```

**Called from main (Line 261):**
```go
db, err = initDB("./users.db")
if err != nil {
	log.Fatal("Failed to initialize database:", err)
}
```

**🤔 What's `*sql.DB`?**

It's NOT a single connection - it's a **connection pool**!

```
Your App
    ↓
Connection Pool (*sql.DB)
    ├─ Connection 1 ──→ Database file
    ├─ Connection 2 ──→ Database file
    └─ Connection 3 ──→ Database file

User Request 1 → Uses Connection 1
User Request 2 → Uses Connection 2
User Request 3 → Uses Connection 1 (reused!)
```

**Benefits:**
- ✅ Reuses connections (faster)
- ✅ Handles concurrency automatically
- ✅ Closes unused connections automatically

**🤔 What's `.Ping()`?**

Tests if the database is actually accessible:
```go
if err = db.Ping(); err != nil {
	// Can't connect to database!
	return nil, err
}
```

Like knocking on a door to see if someone's home!

---

## 📊 Table Creation

### 1. Users Table (Lines 299-310)

```sql
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
);
```

**Let's break it down:**

| Part | What it means |
|------|---------------|
| `CREATE TABLE IF NOT EXISTS` | Create table, but only if it doesn't already exist |
| `id INTEGER PRIMARY KEY` | Unique identifier for each user |
| `AUTOINCREMENT` | Database automatically assigns 1, 2, 3, ... |
| `TEXT` | Stores text/strings |
| `UNIQUE` | No two users can have same value |
| `NOT NULL` | Field must have a value (can't be empty) |
| `DEFAULT FALSE` | New rows start with this value |
| `BOOLEAN` | True or false (SQLite stores as 0 or 1) |
| `DATETIME` | Stores date and time |

**Example data:**
```
id | username | email           | password_hash          | is_verified | is_admin
---+----------+-----------------+------------------------+-------------+---------
1  | admin    | admin@email.com | $2a$10$N9qo8uLO...   | 1           | 1
2  | john_doe | john@email.com  | $2a$10$7hFn3XJ9...   | 1           | 0
3  | jane     | jane@email.com  | $2a$10$M8no9kLP...   | 0           | 0
```

**Field purposes:**

- `verification_token` & `token_expiry`: For email verification
  - User registers → Gets token
  - Clicks email link → Token verified → Set to NULL

- `password_reset_token` & `reset_token_expiry`: For password reset
  - User forgets password → Gets reset token
  - Clicks reset link → Resets password → Set to NULL

---

### 2. Places Table (Lines 312-325)

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

| Concept | Explanation |
|---------|-------------|
| `REAL` | Floating-point numbers (decimals) - for GPS coordinates |
| `DEFAULT 0` | New rows start with 0 |
| `CURRENT_TIMESTAMP` | Auto-fills with current date/time |
| `FOREIGN KEY` | Links to another table (creates relationship) |

**🤔 What's a Foreign Key?**

It creates a relationship between tables:

```
USERS TABLE:
┌────┬──────────┐
│ id │ username │
├────┼──────────┤
│ 2  │ john_doe │  ← User exists
│ 3  │ jane     │
└────┴──────────┘
       ↑
       │ Links to this user
       │
PLACES TABLE:
┌────┬──────────────────┬────────────────────┐
│ id │ title            │ submitted_by_user_id │
├────┼──────────────────┼────────────────────┤
│ 1  │ Prizren Castle   │ 2 ──────────────────┘
│ 2  │ Rugova Canyon    │ 3
└────┴──────────────────┴────────────────────┘
```

**Foreign key ensures:**
- ✅ You can't submit a place with non-existent user ID
- ✅ Database maintains data integrity
- ✅ Can easily find all places by a user

**Example query:**
```sql
SELECT * FROM places WHERE submitted_by_user_id = 2;
-- Returns all places submitted by john_doe
```

---

### 3. Comments Table (Lines 327-337)

```sql
CREATE TABLE IF NOT EXISTS comments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	place_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	content TEXT NOT NULL,
	image_url TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(place_id) REFERENCES places(id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users(id)
);
```

**🤔 What's `ON DELETE CASCADE`?**

When a place is deleted, **automatically delete all its comments too!**

```
Before deleting Place 1:
PLACES: [Place 1, Place 2]
COMMENTS: [Comment on Place 1, Comment on Place 2]

db.Exec("DELETE FROM places WHERE id = 1")

After:
PLACES: [Place 2]
COMMENTS: [Comment on Place 2]  ← Comment on Place 1 auto-deleted!
```

**Without CASCADE:**
```sql
-- Would get an error!
DELETE FROM places WHERE id = 1;
-- Error: foreign key constraint failed
-- (comments still reference this place)

-- Would need to manually delete comments first:
DELETE FROM comments WHERE place_id = 1;
DELETE FROM places WHERE id = 1;
```

**With CASCADE:**
```sql
-- Just delete the place, comments go automatically!
DELETE FROM places WHERE id = 1;
```

---

## 🔧 Database Schema Updates (Lines 367-370)

```go
// Add columns if they don't exist (for updates to existing databases)
db.Exec("ALTER TABLE users ADD COLUMN password_reset_token TEXT")
db.Exec("ALTER TABLE users ADD COLUMN reset_token_expiry DATETIME")
db.Exec("ALTER TABLE comments ADD COLUMN image_url TEXT")
```

**🤔 Why do this?**

When you add features to an existing app, you need to update the database structure.

**Real scenario:**
```
Version 1.0: App doesn't have password reset
            users.db created without password_reset_token column

Version 2.0: Added password reset feature
            Need to add password_reset_token column!

ALTER TABLE adds it to existing databases
(Doesn't error if column already exists in new installs)
```

**This makes your app backwards-compatible with old databases!**

---

## 🌱 Seeding Default Data (Lines 373-378)

```go
// Create default admin user if doesn't exist
var count int
db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)

if count == 0 {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	db.Exec(`INSERT INTO users (username, email, password_hash, is_verified, is_admin)
	         VALUES (?, ?, ?, ?, ?)`,
		"admin", "admin@example.com", string(hashedPassword), true, true)
	log.Println("Created default admin user: admin/admin123")
}
```

**What this does:**
1. Checks if admin user exists
2. If not, creates it with:
   - Username: `admin`
   - Password: `admin123` (hashed with bcrypt)
   - Email verified: `true`
   - Admin privileges: `true`
3. Logs creation

**🚨 Security reminder:** Change the admin password after first login!

---

## 📖 CRUD Operations

**CRUD** = **C**reate, **R**ead, **U**pdate, **D**elete (the 4 basic database operations)

### CREATE - Inserting Data

**Example: Register new user (Lines 420-424):**
```go
_, err = db.Exec(
	`INSERT INTO users (username, email, password_hash, verification_token, token_expiry)
	 VALUES (?, ?, ?, ?, ?)`,
	username, email, string(hashedPassword), token, expiry,
)
```

**🤔 Why the `?` placeholders?**

**❌ DANGEROUS - SQL Injection vulnerability:**
```go
// NEVER do this!
query := "INSERT INTO users (username) VALUES ('" + username + "')"
db.Exec(query)
```

**What if username is:** `'); DROP TABLE users; --`

**Your query becomes:**
```sql
INSERT INTO users (username) VALUES (''); DROP TABLE users; --')
                                           ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
                                           Deletes your entire users table!
```

**✅ SAFE - Parameterized query:**
```go
db.Exec("INSERT INTO users (username) VALUES (?)", username)
```

Go **escapes** the input, making it safe:
```sql
-- username becomes a safe string value
INSERT INTO users (username) VALUES ('`); DROP TABLE users; --')
                                      ↑ Treated as text, not SQL code!
```

**Other CREATE examples:**

**Submit a new place (Lines 914-919):**
```go
_, err = db.Exec(`
	INSERT INTO places (title, description, category, google_maps_link, submitted_by_user_id)
	VALUES (?, ?, ?, ?, ?)`,
	title, description, category, googleMapsLink, user.ID,
)
```

**Add a comment (Lines 950-954):**
```go
_, err := db.Exec(`
	INSERT INTO comments (place_id, user_id, content, image_url)
	VALUES (?, ?, ?, ?)`,
	placeID, user.ID, content, imageURL,
)
```

---

### READ - Querying Data

**Three types of reads:**

#### 1. Single Row - `QueryRow` ⭐

**Use when:** Getting ONE specific record

**Example: Get current user (Lines 338-343):**
```go
var user User
err := db.QueryRow(
	"SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?",
	userID,
).Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)

if err != nil {
	// No user found or database error
	return User{}, err
}
```

**How it works:**
```
1. Execute query looking for user with specific ID
2. Get one row back (or error if not found)
3. Scan fills the User struct fields
4. Return the filled struct
```

**🤔 What's `.Scan()`?**

Scan takes the database row and fills your variables:

```
Database row:  [42, "john_doe", "john@email.com", true, false]
                ↓     ↓           ↓                 ↓      ↓
Scan fills:   user.ID  user.Username  user.Email  user.IsVerified  user.IsAdmin
```

**Must provide addresses with `&`** so Scan can modify them!

#### 2. Multiple Rows - `Query` ⭐⭐

**Use when:** Getting a LIST of records

**Example: Get all users (Lines 597-605):**
```go
rows, err := db.Query("SELECT id, username, email, is_verified, is_admin FROM users ORDER BY id")
if err != nil {
	return nil, err
}
defer rows.Close()  // IMPORTANT: Always close when done!

var users []User
for rows.Next() {
	var u User
	rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
	users = append(users, u)
}
```

**How it works:**
```
1. Execute query (gets multiple rows)
2. rows.Next() moves to first row
3. Scan fills struct from current row
4. Append to slice
5. rows.Next() moves to next row
6. Repeat until no more rows
7. rows.Close() releases resources
```

**⚠️ IMPORTANT:** Always `defer rows.Close()`!

```go
rows, err := db.Query(...)
defer rows.Close()  // ← Don't forget this!
```

If you forget, connections leak and your app slows down!

#### 3. Complex Query with JOIN ⭐⭐⭐

**Use when:** Getting data from MULTIPLE tables

**Example: Get places with submitter info (Lines 608-613):**
```go
rows, err := db.Query(`
	SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
	       p.google_maps_link, p.created_at, p.is_approved, u.username,
	       (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
	FROM places p
	JOIN users u ON p.submitted_by_user_id = u.id
	WHERE p.is_approved = FALSE
	ORDER BY p.created_at DESC
`)
```

**What this complex query does:**

1. **FROM places p** - Get data from places table (alias `p`)
2. **JOIN users u** - Join with users table (alias `u`)
3. **ON p.submitted_by_user_id = u.id** - Match places to their submitters
4. **Subquery** - Count comments for each place
5. **WHERE p.is_approved = FALSE** - Only unapproved places
6. **ORDER BY p.created_at DESC** - Newest first

**Visual representation:**

```
PLACES (p):                   USERS (u):
┌────┬─────────────┬──────┐  ┌────┬──────────┐
│ id │ title       │ user │  │ id │ username │
├────┼─────────────┼──────┤  ├────┼──────────┤
│ 1  │ Castle      │ 2    │─→│ 2  │ john_doe │
│ 2  │ Canyon      │ 3    │─→│ 3  │ jane     │
└────┴─────────────┴──────┘  └────┴──────────┘
        ↓ JOIN ON p.user = u.id
Result:
┌────┬─────────────┬──────────┬──────────────┐
│ id │ title       │ username │ comment_count│
├────┼─────────────┼──────────┼──────────────┤
│ 1  │ Castle      │ john_doe │ 5            │
│ 2  │ Canyon      │ jane     │ 3            │
└────┴─────────────┴──────────┴──────────────┘
```

**More JOIN examples:**

**Get place with comments (Lines 832-843):**
```go
rows, err := db.Query(`
	SELECT c.id, c.place_id, c.user_id, u.username, c.content,
	       c.image_url, c.created_at
	FROM comments c
	JOIN users u ON c.user_id = u.id
	WHERE c.place_id = ?
	ORDER BY c.created_at DESC
`, placeID)
```

Gets all comments for a place, including the username of who posted each comment.

---

### UPDATE - Modifying Data

**Use when:** Changing existing records

**Example: Verify user's email (Lines 509-511):**
```go
result, err := db.Exec(
	`UPDATE users
	 SET is_verified = TRUE, verification_token = NULL
	 WHERE verification_token = ? AND token_expiry > ?`,
	token, time.Now(),
)
```

**What this does:**
1. Find user with matching token that hasn't expired
2. Set `is_verified` to TRUE
3. Clear `verification_token` (set to NULL)

**Checking if it worked:**
```go
rowsAffected, _ := result.RowsAffected()
if rowsAffected == 0 {
	// No rows updated = invalid or expired token
}
```

**More UPDATE examples:**

**Approve a place (Line 633):**
```go
_, err := db.Exec(
	"UPDATE places SET is_approved = TRUE, latitude = ?, longitude = ? WHERE id = ?",
	lat, lng, placeID,
)
```

**Change password (Line 732):**
```go
_, err = db.Exec(
	"UPDATE users SET password_hash = ? WHERE id = ?",
	string(hashedPassword), user.ID,
)
```

**Reset password and clear token (Lines 552-554):**
```go
result, err := db.Exec(
	`UPDATE users
	 SET password_hash = ?, password_reset_token = NULL, reset_token_expiry = NULL
	 WHERE password_reset_token = ? AND reset_token_expiry > ?`,
	string(hashedPassword), token, time.Now(),
)
```

---

### DELETE - Removing Data

**Use when:** Permanently removing records

**Example: Delete a place (Lines 640-643):**
```go
// Delete comments first (or use CASCADE)
_, err := db.Exec("DELETE FROM comments WHERE place_id = ?", placeID)

// Then delete the place
_, err = db.Exec("DELETE FROM places WHERE id = ?", placeID)
```

**🤔 Why delete comments first?**

If comments table has `FOREIGN KEY ... ON DELETE CASCADE`, it happens automatically.
Otherwise, you must delete comments first (can't delete place while comments reference it).

**Example: Delete user account (Lines 764-771):**
```go
// Delete user's comments
db.Exec("DELETE FROM comments WHERE user_id = ?", user.ID)

// Delete user's places
db.Exec("DELETE FROM places WHERE submitted_by_user_id = ?", user.ID)

// Delete user account
_, err = db.Exec("DELETE FROM users WHERE id = ?", user.ID)
```

**Order matters!** Delete related records first, then the main record.

```
Correct order:
1. Delete comments by user
2. Delete places by user
3. Delete user

Wrong order:
1. Delete user ← ERROR! Still has comments and places
```

---

## 🔍 Common Query Patterns

### 1. Count Records

**Example: Count users (Line 374):**
```go
var count int
err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
// count now holds the number of matching users
```

**Example: Count pending places (Line 618):**
```go
var pendingCount int
db.QueryRow("SELECT COUNT(*) FROM places WHERE is_approved = FALSE").Scan(&pendingCount)
```

### 2. Check if Record Exists

```go
var exists bool
err := db.QueryRow(
	"SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)",
	email,
).Scan(&exists)

if exists {
	// Email already registered
}
```

**How it works:**
- `EXISTS(...)` returns true if subquery finds any rows
- `SELECT 1` is a dummy value (we only care about existence, not data)

### 3. LIKE Search (Case-Insensitive)

**Example: Search places (Lines 768-789):**
```go
searchParam := "%" + strings.ToLower(searchQuery) + "%"

rows, err := db.Query(`
	SELECT * FROM places
	WHERE is_approved = TRUE
	  AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)
`, searchParam, searchParam)
```

**🤔 How LIKE works:**

`%` is a wildcard (matches anything)

```
User searches: "castle"
searchParam becomes: "%castle%"

Matches:
✓ "Prizren Castle"     ← contains "castle"
✓ "The Old Castle"     ← contains "castle"
✓ "Medieval Castles"   ← contains "castle"
✓ "CASTLE OF NOVO"     ← LOWER() makes it match

Doesn't match:
✗ "Monastery"          ← no "castle"
✗ "Nature Trail"       ← no "castle"
```

**`LOWER()` ensures case-insensitive matching:**
```sql
LOWER("Prizren CASTLE") = "prizren castle"
LOWER("castle")         = "castle"
                          ↑ Match!
```

### 4. Dynamic WHERE Clauses

**Example: Build query based on filters (Lines 774-789):**
```go
query := "SELECT * FROM places WHERE is_approved = TRUE"
args := []interface{}{}

// Add category filter if provided
if category != "" {
	query += " AND category = ?"
	args = append(args, category)
}

// Add search filter if provided
if searchQuery != "" {
	query += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)"
	searchParam := "%" + strings.ToLower(searchQuery) + "%"
	args = append(args, searchParam, searchParam)
}

// Execute with dynamic arguments
rows, err := db.Query(query, args...)
```

**How it works:**

```
No filters:
  Query: SELECT * FROM places WHERE is_approved = TRUE
  Args: []

With category "Historical":
  Query: SELECT * FROM places WHERE is_approved = TRUE AND category = ?
  Args: ["Historical"]

With category AND search "castle":
  Query: SELECT * FROM places WHERE is_approved = TRUE AND category = ? AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)
  Args: ["Historical", "%castle%", "%castle%"]
```

**🤔 What's `args...`?**

The `...` spreads the slice into individual arguments:

```go
args := []interface{}{"Historical", "%castle%", "%castle%"}

db.Query(query, args...)
// Same as:
db.Query(query, "Historical", "%castle%", "%castle%")
```

---

## ⚡ Performance Tips

### 1. Indexes (Not in your code yet)

**What:** Speed up searches on specific columns

```sql
CREATE INDEX idx_places_category ON places(category);
CREATE INDEX idx_places_approved ON places(is_approved);
```

**Without index:**
```
Search for category="Historical"
→ Scan ALL 10,000 places one by one
→ Takes 500ms
```

**With index:**
```
Search for category="Historical"
→ Index lookup finds matching places instantly
→ Takes 5ms (100x faster!)
```

**When to use:** Columns you search/filter frequently

### 2. Prepared Statements (Not in your code yet)

**What:** Compile query once, execute many times

```go
// Prepare query once
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
defer stmt.Close()

// Use many times (faster!)
for _, id := range userIDs {
	stmt.QueryRow(id)
}
```

**Use when:** Running same query many times in a loop

### 3. Transactions (Not in your code yet)

**What:** Group operations - all succeed or all fail

```go
// Start transaction
tx, err := db.Begin()
if err != nil {
	return err
}

// Do multiple operations
tx.Exec("INSERT INTO users ...")
tx.Exec("INSERT INTO places ...")
tx.Exec("UPDATE comments ...")

// All succeeded? Commit!
if err := tx.Commit(); err != nil {
	tx.Rollback()  // Something failed, undo everything!
	return err
}
```

**Use case:** Transferring money between accounts
- Deduct $100 from Account A
- Add $100 to Account B
- Either BOTH happen or NEITHER (prevents losing money!)

---

## 🎓 Practice Exercise

**Add a "favorites" feature!**

Users can favorite places they like.

**Step 1: Create table**
```sql
CREATE TABLE IF NOT EXISTS favorites (
	user_id INTEGER NOT NULL,
	place_id INTEGER NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id, place_id),
	FOREIGN KEY(user_id) REFERENCES users(id),
	FOREIGN KEY(place_id) REFERENCES places(id) ON DELETE CASCADE
);
```

**Step 2: Add favorite**
```go
func addFavorite(userID, placeID int) error {
	_, err := db.Exec(
		"INSERT INTO favorites (user_id, place_id) VALUES (?, ?)",
		userID, placeID,
	)
	return err
}
```

**Step 3: Remove favorite**
```go
func removeFavorite(userID, placeID int) error {
	_, err := db.Exec(
		"DELETE FROM favorites WHERE user_id = ? AND place_id = ?",
		userID, placeID,
	)
	return err
}
```

**Step 4: Check if favorited**
```go
func isFavorited(userID, placeID int) (bool, error) {
	var exists bool
	err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM favorites WHERE user_id = ? AND place_id = ?)",
		userID, placeID,
	).Scan(&exists)
	return exists, err
}
```

**Step 5: Get user's favorites**
```go
func getUserFavorites(userID int) ([]Place, error) {
	rows, err := db.Query(`
		SELECT p.id, p.title, p.description, p.category,
		       p.latitude, p.longitude, p.google_maps_link
		FROM places p
		JOIN favorites f ON p.id = f.place_id
		WHERE f.user_id = ?
		ORDER BY f.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var places []Place
	for rows.Next() {
		var p Place
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category,
		          &p.Latitude, &p.Longitude, &p.GoogleMapsLink)
		places = append(places, p)
	}
	return places, nil
}
```

---

## 💡 Key Takeaways

✅ **`*sql.DB` is a connection pool** - Manages multiple connections efficiently
✅ **Always use `?` placeholders** - Prevents SQL injection attacks
✅ **`QueryRow` for one, `Query` for many** - Choose the right tool
✅ **Always `defer rows.Close()`** - Prevents connection leaks
✅ **Foreign keys maintain relationships** - Links between tables
✅ **CASCADE automatically deletes related records** - Clean up easily
✅ **LIKE with %** - Flexible text search
✅ **JOIN combines tables** - Get related data in one query
✅ **Dynamic queries with append** - Build filters on the fly

---

## 🚀 Next Steps

Now you understand how data flows between structs and the database! Next, let's see how web requests trigger these database operations.

**Next chapter:** [HTTP Routing and Handlers](06-http-routing-handlers.md)
Learn how URLs become actions!

---

**Remember:** The database is the heart of your app - it's where all the important data lives safely! 💾

---

*Happy coding! Next up: Web routing* 💾➡️🌐
