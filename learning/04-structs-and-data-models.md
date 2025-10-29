# Chapter 4: Structs and Data Models

## Introduction

Structs are the foundation of your application's data. They define the shape of information as it flows between the database, your Go code, and the frontend. This chapter will help you understand every struct in your code and how they work together.

---

## What Are Structs?

A **struct** is a custom data type that groups related fields together. Think of it like a template or blueprint for data.

**Analogy:**
```
A struct is like a form:
┌─────────────────────┐
│  User Registration  │
├─────────────────────┤
│ Name:    [____]     │
│ Email:   [____]     │
│ Password:[____]     │
└─────────────────────┘
```

Each field has a name and a type!

---

## Section 1: Core Data Models (Lines 63-101)

### 1.1 The User Struct (Lines 66-75)

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

**Field-by-field breakdown:**

| Field | Type | Purpose | Example Value |
|-------|------|---------|---------------|
| `ID` | `int` | Unique identifier | `1`, `2`, `42` |
| `Username` | `string` | Display name | `"john_doe"` |
| `Email` | `string` | Contact email | `"john@example.com"` |
| `PasswordHash` | `string` | Encrypted password | `"$2a$10$N9qo..."` |
| `IsVerified` | `bool` | Email verified? | `true` / `false` |
| `IsAdmin` | `bool` | Has admin rights? | `true` / `false` |
| `VerificationToken` | `sql.NullString` | Email verification token | `"a7f3b82c..."` or NULL |
| `TokenExpiry` | `sql.NullTime` | Token expiration | `2024-01-16 10:30:00` or NULL |

**Special Types Explained:**

**`sql.NullString`:**
- Regular `string` in Go cannot be NULL
- Database columns CAN be NULL
- `sql.NullString` bridges this gap

```go
type NullString struct {
    String string  // The actual value
    Valid  bool    // Is it valid (non-NULL)?
}
```

**Usage example:**
```go
if user.VerificationToken.Valid {
    token := user.VerificationToken.String
    // Use the token
} else {
    // Token is NULL (user already verified)
}
```

**Why PasswordHash instead of Password?**
- NEVER store plain passwords!
- Hash is one-way: password → hash (easy)
- Reverse: hash → password (impossible without massive computing power)

---

### 1.2 The Place Struct (Lines 78-91)

```go
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
```

**Understanding Struct Tags:**

The `` `json:"ID"` `` parts are **struct tags**. They tell the JSON encoder how to name fields.

```go
place := Place{
    ID: 42,
    Title: "Prizren Castle",
}

// When converted to JSON:
{
    "ID": 42,
    "Title": "Prizren Castle"
}
```

**Without tags, Go would default to the field name.**

**Field purposes:**

| Field | What It Stores | Why It's Needed |
|-------|----------------|-----------------|
| `ID` | Database primary key | Unique identifier |
| `Title` | Place name | "Prizren Castle" |
| `Description` | Details about place | "Historic fortress..." |
| `Category` | Type of place | "Culture", "Nature", etc. |
| `Latitude` | GPS coordinate | `42.6026` |
| `Longitude` | GPS coordinate | `20.9030` |
| `GoogleMapsLink` | URL to Google Maps | For users to get directions |
| `SubmittedByUserID` | Who added it | Links to User.ID |
| `IsApproved` | Admin approved? | Only approved places show on map |
| `CreatedAt` | Submission timestamp | When it was added |
| `SubmittedByUsername` | Display name | Shown on frontend |
| `CommentCount` | Number of comments | Displayed on place cards |

**Note:** `SubmittedByUsername` and `CommentCount` are NOT in the database! They're computed when querying:

```go
// Line 741: CommentCount is calculated
SELECT (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
```

---

### 1.3 The Comment Struct (Lines 94-101)

```go
type Comment struct {
    ID        int
    PlaceID   int
    UserID    int
    Username  string
    Content   string
    CreatedAt time.Time
}
```

**Relationships:**
```
Place (ID: 42)
    ├── Comment (ID: 1, PlaceID: 42, UserID: 5)
    ├── Comment (ID: 2, PlaceID: 42, UserID: 7)
    └── Comment (ID: 3, PlaceID: 42, UserID: 5)

User (ID: 5)
    ├── Comment (ID: 1)
    └── Comment (ID: 3)
```

**Why both UserID and Username?**
- `UserID` - Links to the users table (foreign key)
- `Username` - Fetched via JOIN for display

**Example query (line 836):**
```sql
SELECT c.id, c.content, c.created_at, u.username
FROM comments c
JOIN users u ON c.user_id = u.id
WHERE c.place_id = ?
```

This fills all fields of the Comment struct in one query!

---

## Section 2: Page Data Models (Lines 103-151)

These structs define what data gets passed to HTML templates.

### 2.1 AdminPageData (Lines 105-111)

```go
type AdminPageData struct {
    CurrentUser  User
    Users        []User
    Message      string
    Error        string
    PendingCount int
}
```

**Used in:** Admin panel (line 619)

**Purpose:** Passes data to the admin dashboard template

**Example:**
```go
data := AdminPageData{
    CurrentUser: loggedInAdmin,
    Users: allUsersFromDB,
    Message: "User deleted successfully",
    Error: "",
    PendingCount: 5,
}
renderTemplate(w, "admin", PageBundle{Data: data})
```

**In the template:**
```html
{{if .Data.Message}}
    <div class="alert-success">{{.Data.Message}}</div>
{{end}}

<h2>There are {{.Data.PendingCount}} pending places</h2>

{{range .Data.Users}}
    <tr>
        <td>{{.Username}}</td>
        <td>{{.Email}}</td>
    </tr>
{{end}}
```

---

### 2.2 DashboardPageData (Lines 120-122)

```go
type DashboardPageData struct {
    CurrentUser User
}
```

**Used in:** User dashboard (line 544)

**Purpose:** Shows personalized welcome message

**Simple because the dashboard just needs to know who you are!**

---

### 2.3 MessagePageData (Lines 124-127)

```go
type MessagePageData struct {
    Title   string
    Message string
}
```

**Used in:** Generic message pages (verification success, errors, etc.)

**Example (line 532):**
```go
renderTemplate(w, "message", PageBundle{
    Data: MessagePageData{
        Title:   "Email Verified",
        Message: "Your email has been successfully verified.",
    },
})
```

**Template (line 1782):**
```html
<h1>{{.Data.Title}}</h1>
<p>{{.Data.Message}}</p>
```

---

### 2.4 PlacesListPageData (Lines 129-134)

```go
type PlacesListPageData struct {
    Places       []Place
    SearchQuery  string
    Category     string
    TotalMatches int
}
```

**Used in:** Places listing page (line 790)

**Purpose:** Display search results with metadata

**Example:**
```go
data := PlacesListPageData{
    Places: matchingPlaces,
    SearchQuery: "restaurant",
    Category: "Restaurant",
    TotalMatches: 15,
}
```

**Template usage:**
```html
<p>Found {{.Data.TotalMatches}} places matching "{{.Data.SearchQuery}}"</p>

{{range .Data.Places}}
    <div class="place-card">
        <h3>{{.Title}}</h3>
    </div>
{{end}}
```

---

### 2.5 PlaceDetailPageData (Lines 136-140)

```go
type PlaceDetailPageData struct {
    Place       Place
    Comments    []Comment
    CurrentUser User
}
```

**Used in:** Individual place page (line 855)

**Purpose:** Show a single place with all its comments

**Why CurrentUser?**
- To show/hide comment form based on login status
- To display username if commenting

---

### 2.6 PageBundle (Lines 146-151)

```go
type PageBundle struct {
    PageName    string
    Data        interface{}
    CurrentUser User
}
```

**This is a wrapper struct!** It bundles page-specific data with universal data.

**`interface{}`:**
- Means "any type"
- Allows `Data` to be `AdminPageData`, `DashboardPageData`, etc.

**Usage pattern:**
```go
renderTemplate(w, "admin", PageBundle{
    PageName:    "admin",
    Data:        AdminPageData{...},  // Specific data
    CurrentUser: loggedInUser,         // Always included
})
```

**In templates:**
```html
<!-- CurrentUser is always available -->
{{if .CurrentUser.ID}}
    <span>Hello, {{.CurrentUser.Username}}</span>
{{end}}

<!-- Data contains page-specific stuff -->
{{.Data.Message}}
```

---

## Section 3: API Models (Lines 152-184)

These structs handle JSON communication with the frontend.

### 3.1 AI Chat Request/Response

**Request (Lines 154-156):**
```go
type AIChatRequest struct {
    Prompt string `json:"prompt"`
}
```

**JavaScript sends:**
```json
{
    "prompt": "Find restaurants in Prizren"
}
```

**Response (Lines 158-161):**
```go
type AIChatResponse struct {
    Type    string      `json:"type"`
    Content interface{} `json:"content,omitempty"`
}
```

**`interface{}`** allows Content to be:
- A string: `"I can help you..."`
- An array of places: `[{Title: "..."}, {Title: "..."}]`

**`omitempty`** means: don't include this field in JSON if it's empty.

**Example responses:**
```json
// Type 1: Text response
{
    "type": "other",
    "content": "I can help with appointments or places"
}

// Type 2: Places array
{
    "type": "places",
    "content": [
        {"ID": 1, "Title": "Restaurant ABC"},
        {"ID": 2, "Title": "Cafe XYZ"}
    ]
}
```

---

### 3.2 Gemini API Models (Lines 163-184)

These structs match Google's Gemini API format.

**Request structure:**
```go
type GeminiRequest struct {
    Contents []GeminiContent `json:"contents"`
}
type GeminiContent struct {
    Parts []GeminiPart `json:"parts"`
}
type GeminiPart struct {
    Text string `json:"text"`
}
```

**Nested structure visualization:**
```
GeminiRequest
  └── Contents: []GeminiContent
        └── [0]: GeminiContent
              └── Parts: []GeminiPart
                    └── [0]: GeminiPart
                          └── Text: "Classify: I want to find a restaurant"
```

**Built in your code (line 1047):**
```go
geminiReq := GeminiRequest{
    Contents: []GeminiContent{
        {
            Parts: []GeminiPart{
                {Text: aiSystemPrompt + "\n\nUser: " + prompt},
            },
        },
    },
}
```

**Converts to JSON:**
```json
{
    "contents": [
        {
            "parts": [
                {
                    "text": "You are a classification bot...\n\nUser: Find restaurants"
                }
            ]
        }
    ]
}
```

**Response structure (Lines 173-184):**
```go
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
```

**Gemini returns:**
```json
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {"text": "places"}
                ]
            }
        }
    ]
}
```

**Extracting the answer (line 1082):**
```go
classification := geminiResp.Candidates[0].Content.Parts[0].Text
// Result: "places"
```

---

## How Structs Flow Through Your Application

### Example: User Registration

```
1. Browser submits form
    ↓
2. Handler receives data
    username := r.FormValue("username")
    email := r.FormValue("email")
    password := r.FormValue("password")
    ↓
3. Hash password
    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    ↓
4. Insert into database
    db.Exec("INSERT INTO users (username, email, password_hash, ...) VALUES (?, ?, ?, ...)",
        username, email, string(hashedPassword), token, expiry)
    ↓
5. Later: Reading from database
    var user User
    db.QueryRow("SELECT id, username, email, ... FROM users WHERE username = ?", username).
        Scan(&user.ID, &user.Username, &user.Email, ...)
    ↓
6. Struct is now populated:
    user.ID = 42
    user.Username = "john_doe"
    user.Email = "john@example.com"
    ↓
7. Pass to template
    renderTemplate(w, "dashboard", PageBundle{
        CurrentUser: user,
    })
    ↓
8. Template accesses fields
    <h1>Welcome, {{.CurrentUser.Username}}!</h1>
```

---

## Struct Methods (Not Used in Your Code, But Important)

Structs can have **methods** - functions attached to them.

**Example (not in your code):**
```go
func (u User) IsActive() bool {
    return u.IsVerified && !u.IsBanned
}

// Usage
if user.IsActive() {
    // Allow access
}
```

**Your code could benefit from methods like:**
```go
func (p Place) GetMapURL() string {
    return fmt.Sprintf("https://maps.google.com/?q=%f,%f", p.Latitude, p.Longitude)
}

func (u User) HasPermission(action string) bool {
    if u.IsAdmin {
        return true
    }
    // Check specific permissions
}
```

---

## Zero Values

Uninitialized struct fields have **zero values**:

```go
var user User
// user.ID = 0
// user.Username = ""
// user.Email = ""
// user.IsVerified = false
// user.IsAdmin = false
```

**This matters when:**
```go
if user.ID == 0 {
    // No user loaded from database
}

if user.Username == "" {
    // Field not set
}
```

---

## Embedded Structs (Not Used in Your Code)

You can nest structs inside each other:

```go
type Address struct {
    Street string
    City   string
}

type Person struct {
    Name    string
    Address Address  // Nested
}

person := Person{
    Name: "John",
    Address: Address{
        Street: "123 Main St",
        City:   "Prizren",
    },
}

fmt.Println(person.Address.City)  // "Prizren"
```

---

## Practice Exercise

### Exercise 1: Create a Place

Fill in the struct:

```go
place := Place{
    // Add a new restaurant
    Title: ?,
    Description: ?,
    Category: ?,
    Latitude: 42.6026,
    Longitude: 20.9030,
    IsApproved: false,
    CreatedAt: time.Now(),
}
```

**Solution:**
```go
place := Place{
    Title: "Pizza Palace",
    Description: "Best pizza in Prizren",
    Category: "Restaurant",
    Latitude: 42.6026,
    Longitude: 20.9030,
    GoogleMapsLink: "https://maps.google.com/?q=42.6026,20.9030",
    SubmittedByUserID: 1,
    IsApproved: false,
    CreatedAt: time.Now(),
}
```

### Exercise 2: Understanding JSON Tags

Given this struct:
```go
type Book struct {
    Title  string `json:"title"`
    Author string `json:"author"`
    Pages  int    `json:"page_count"`
}
```

What JSON is produced?

```go
book := Book{Title: "Go Programming", Author: "John", Pages: 300}
json.Marshal(book)
```

**Answer:**
```json
{
    "title": "Go Programming",
    "author": "John",
    "page_count": 300
}
```

---

## Key Takeaways

✅ **Structs** - Custom types that group related data
✅ **Fields** - Each has a name and type
✅ **Tags** - Control JSON encoding (`` `json:"name"` ``)
✅ **sql.NullString/NullTime** - Handle NULL database values
✅ **interface{}** - Can hold any type
✅ **PageBundle** - Universal wrapper for template data
✅ **Zero values** - Default values for uninitialized fields

**Your code uses structs for:**
1. Database models (User, Place, Comment)
2. Template data (AdminPageData, DashboardPageData, etc.)
3. API communication (AIChatRequest, GeminiResponse)

---

**Next Chapter:** Database operations - how your structs interact with SQLite!
