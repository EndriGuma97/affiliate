# Chapter 4: Structs and Data Models 🏗️

## Welcome to Data Structures!

Structs are Go's way of creating custom data types - like blueprints that define how to organize related information together!

**Think of it like:**
- A form with labeled boxes: Name [____] Email [____] Phone [____]
- Each box has a label (field name) and holds specific data (field type)

---

## 📍 Where to Find Them

Your `main.go` has **15 different structs** in lines **74-184**:

**Core Data Models (Lines 74-105):**
- `User` - User accounts
- `Place` - Tourist locations
- `Comment` - User comments on places

**Page Data Models (Lines 109-152):**
- Data structures for rendering HTML pages

**API Models (Lines 156-184):**
- Data structures for JSON APIs (AJAX and Gemini AI)

---

## 🎯 What is a Struct?

**Simple example:**
```go
type Person struct {
	Name  string  // Text field
	Age   int     // Number field
	Email string  // Text field
}

// Create a person
john := Person{
	Name:  "John Doe",
	Age:   30,
	Email: "john@example.com",
}

// Access fields
fmt.Println(john.Name)   // "John Doe"
fmt.Println(john.Age)    // 30
```

**Why use structs?**
- ✅ Organize related data together
- ✅ Type-safe (Go checks you use correct types)
- ✅ Easy to pass around (one variable instead of many)
- ✅ Self-documenting (field names explain what data means)

---

## 📦 PART 1: Core Data Models

These represent the main entities in your app.

### 1. User Struct (Lines 74-83)

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

**Field-by-field explanation:**

| Field | Type | What it stores | Example |
|-------|------|----------------|---------|
| `ID` | `int` | Unique user number | `42` |
| `Username` | `string` | Display name | `"john_doe"` |
| `Email` | `string` | Email address | `"john@example.com"` |
| `PasswordHash` | `string` | Encrypted password (NOT plain text!) | `"$2a$10$N9qo..."` |
| `IsVerified` | `bool` | Email confirmed? | `true` or `false` |
| `IsAdmin` | `bool` | Has admin powers? | `true` or `false` |
| `VerificationToken` | `sql.NullString` | Email verification code | `"a7f3b82c..."` or `NULL` |
| `TokenExpiry` | `sql.NullTime` | When token expires | `2024-01-16` or `NULL` |

**🤔 What's `sql.NullString` and `sql.NullTime`?**

In databases, fields can be **NULL** (empty/no value). Regular Go strings and times can't be NULL, so we use special types:

```go
// Regular string - can't be NULL
var name string = ""  // Empty string, but not NULL

// Nullable string - can be NULL
var token sql.NullString
token.Valid = false  // This is NULL
token.String = ""

token.Valid = true   // This has a value
token.String = "abc123"
```

**Real scenario:**
```
User registers → VerificationToken = "abc123", TokenExpiry = tomorrow
User verifies email → VerificationToken = NULL, TokenExpiry = NULL (cleared)
```

**Where User is used (Line 338-343):**
```go
func getCurrentUser(r *http.Request) (User, error) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["user_id"].(int)

	var user User
	err := db.QueryRow(
		"SELECT id, username, email, is_verified, is_admin FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.IsVerified, &user.IsAdmin)

	return user, err
}
```

**What this does:**
1. Gets user ID from session cookie
2. Creates empty `User` struct
3. Fills it with database data using `Scan`
4. Returns the filled struct

---

### 2. Place Struct (Lines 86-99)

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

**🤔 What are those backtick things?**

The `` `json:"ID"` `` parts are **struct tags** - they control how the struct converts to JSON.

**Example:**
```go
place := Place{
	ID:    42,
	Title: "Prizren Castle",
}

// Convert to JSON
jsonBytes, _ := json.Marshal(place)
// Result: {"ID": 42, "Title": "Prizren Castle"}
//          ↑ Uses tag name, not field name
```

**Without tags vs with tags:**
```go
// Without custom tags
type Place struct {
	ID    int
	Title string
}
// JSON: {"ID": 42, "Title": "Castle"}

// With custom tags for lowercase
type Place struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}
// JSON: {"id": 42, "title": "Castle"}
```

**Your code uses capitalized tags to match JavaScript expectations!**

**Field breakdown:**

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `ID` | `int` | Unique place identifier | `42` |
| `Title` | `string` | Place name | `"Prizren Castle"` |
| `Description` | `string` | About the place | `"Medieval fortress with panoramic views"` |
| `Category` | `string` | Type of place | `"Historical"`, `"Nature"`, `"Food"` |
| `Latitude` | `float64` | GPS north/south | `42.2141` |
| `Longitude` | `float64` | GPS east/west | `20.7397` |
| `GoogleMapsLink` | `string` | Link to maps | `"https://maps.google.com/..."` |
| `SubmittedByUserID` | `int` | Who added it | `7` |
| `IsApproved` | `bool` | Admin approved? | `false` (pending) or `true` (visible) |
| `CreatedAt` | `time.Time` | When submitted | `2024-01-15 10:30:00` |
| `SubmittedByUsername` | `string` | Submitter's name | `"john_doe"` |
| `CommentCount` | `int` | How many comments | `12` |

**🤔 Why `float64` for coordinates?**

GPS coordinates have many decimal places:
```
Latitude:  42.2141253
Longitude: 20.7397421
           ↑ These decimals matter!
```

`float64` = 64-bit floating-point number (handles decimals)

**Where Place is used (Lines 760-797):**
```go
func placesAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Build query based on search/filter
	query := "SELECT * FROM places WHERE is_approved = TRUE"

	// Execute query
	rows, err := db.Query(query, args...)

	// Convert rows to Place structs
	var places []Place
	for rows.Next() {
		var p Place
		rows.Scan(&p.ID, &p.Title, &p.Description, ...)
		places = append(places, p)
	}

	// Send as JSON
	json.NewEncoder(w).Encode(places)
}
```

**Flow:**
```
1. Query database
2. Loop through results
3. Fill Place struct for each row
4. Add to slice of Places
5. Convert entire slice to JSON
6. Send to browser
```

---

### 3. Comment Struct (Lines 102-110)

```go
type Comment struct {
	ID        int
	PlaceID   int
	UserID    int
	Username  string
	Content   string
	ImageURL  string
	CreatedAt time.Time
}
```

**Simple structure for comments on places.**

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `ID` | `int` | Unique comment ID | `123` |
| `PlaceID` | `int` | Which place | `42` (links to Place.ID) |
| `UserID` | `int` | Who wrote it | `7` (links to User.ID) |
| `Username` | `string` | Commenter's name | `"jane_smith"` |
| `Content` | `string` | The comment text | `"Beautiful place! Visited in summer."` |
| `ImageURL` | `string` | Optional image | `"https://..."` or `""` |
| `CreatedAt` | `time.Time` | When posted | `2024-01-15 14:30:00` |

**🤔 Why store both UserID and Username?**

**Option 1: Only UserID**
```go
type Comment struct {
	UserID int  // Need to query users table every time to get name
}
// To display: Extra database query needed!
```

**Option 2: Both (your approach)**
```go
type Comment struct {
	UserID   int     // For relationships (who wrote it)
	Username string  // For fast display (no extra query)
}
// Can display immediately!
```

**Trade-off:**
- ✅ Faster (no extra queries when showing comments)
- ❌ Slight data duplication (username stored twice)

For apps that display comments frequently, this is the right choice!

**Where Comment is used (Lines 832-858):**
```go
func placeDetailHandler(w http.ResponseWriter, r *http.Request) {
	// ... get place ...

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
		rows.Scan(&c.ID, &c.PlaceID, &c.UserID, &c.Username,
		          &c.Content, &c.ImageURL, &c.CreatedAt)
		comments = append(comments, c)
	}

	// Pass to template
	renderTemplate(w, "place_detail", PageBundle{
		Data: PlaceDetailPageData{
			Place:    place,
			Comments: comments,  // All comments as slice
		},
	})
}
```

---

## 📄 PART 2: Page Data Models

These structs hold data for rendering HTML pages. They're like containers that carry all the info a page needs.

### 4. AdminPageData (Lines 114-120)

```go
type AdminPageData struct {
	CurrentUser  User
	Users        []User
	Message      string
	Error        string
	PendingCount int
}
```

**Used for the admin user management page.**

**What each field is for:**

| Field | Purpose |
|-------|---------|
| `CurrentUser` | Admin viewing the page (for header) |
| `Users` | List of all users to display |
| `Message` | Success message (green) |
| `Error` | Error message (red) |
| `PendingCount` | Badge showing # of pending places |

**Where it's used (Lines 612-622):**
```go
func adminHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	// Get all users
	rows, err := db.Query("SELECT id, username, email, is_verified, is_admin FROM users")
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsVerified, &u.IsAdmin)
		users = append(users, u)
	}

	// Count pending places
	var pendingCount int
	db.QueryRow("SELECT COUNT(*) FROM places WHERE is_approved = FALSE").Scan(&pendingCount)

	// Render page
	renderTemplate(w, "admin", PageBundle{
		PageName: "admin",
		Data: AdminPageData{
			CurrentUser:  user,
			Users:        users,
			Message:      "User updated successfully",
			PendingCount: pendingCount,
		},
		CurrentUser: user,
	})
}
```

**In the HTML template:**
```html
{{if .Data.Message}}
	<div class="success-message">{{.Data.Message}}</div>
{{end}}

<h2>User Management</h2>
<span class="badge">{{.Data.PendingCount}} pending places</span>

<table>
	{{range .Data.Users}}
		<tr>
			<td>{{.Username}}</td>
			<td>{{.Email}}</td>
			<td>{{if .IsAdmin}}Admin{{else}}User{{end}}</td>
		</tr>
	{{end}}
</table>
```

---

### 5. AdminPlacesPageData (Lines 122-127)

```go
type AdminPlacesPageData struct {
	CurrentUser   User
	PendingPlaces []Place
	Message       string
	Error         string
}
```

**For the admin page where places are reviewed and approved.**

Similar structure to AdminPageData, but focused on places instead of users.

---

### 6. DashboardPageData (Lines 129-131)

```go
type DashboardPageData struct {
	CurrentUser User
}
```

**Simplest page data model!**

The dashboard just needs to know who's logged in to show personalized content.

---

### 7. MessagePageData (Lines 133-136)

```go
type MessagePageData struct {
	Title   string
	Message string
}
```

**For simple information/confirmation pages.**

**Example usage (Line 447):**
```go
renderTemplate(w, "message", PageBundle{
	Data: MessagePageData{
		Title:   "Email Verified",
		Message: "Your email has been successfully verified. You can now log in.",
	},
})
```

**Renders as:**
```
╔═══════════════════════════╗
║    Email Verified         ║
╠═══════════════════════════╣
║                           ║
║ Your email has been       ║
║ successfully verified.    ║
║ You can now log in.       ║
║                           ║
║    [Back to Home]         ║
╚═══════════════════════════╝
```

---

### 8. PlacesListPageData (Lines 138-143)

```go
type PlacesListPageData struct {
	Places       []Place
	SearchQuery  string
	Category     string
	TotalMatches int
}
```

**For the places listing/browse page with search and filters.**

**Example:**
```go
PlacesListPageData{
	Places: []Place{
		{Title: "Prizren Castle", Category: "Historical"},
		{Title: "Rugova Canyon", Category: "Nature"},
	},
	SearchQuery:  "castle",
	Category:     "Historical",
	TotalMatches: 2,
}
```

**In template:**
```html
<h2>Found {{.TotalMatches}} places
    {{if .SearchQuery}}matching "{{.SearchQuery}}"{{end}}
    {{if .Category}}in category "{{.Category}}"{{end}}
</h2>

{{range .Places}}
	<div class="place-card">
		<h3>{{.Title}}</h3>
		<span class="category">{{.Category}}</span>
	</div>
{{end}}
```

---

### 9. PlaceDetailPageData (Lines 145-149)

```go
type PlaceDetailPageData struct {
	Place       Place
	Comments    []Comment
	CurrentUser User
}
```

**For showing a single place with all its details and comments.**

```go
PlaceDetailPageData{
	Place: Place{
		Title: "Prizren Castle",
		Description: "Medieval fortress...",
		CommentCount: 5,
	},
	Comments: []Comment{
		{Username: "john", Content: "Amazing!"},
		{Username: "jane", Content: "Must visit!"},
	},
	CurrentUser: user,  // To show "Add Comment" form if logged in
}
```

---

### 10. ChatPageData (Lines 151-153)

```go
type ChatPageData struct {
	Greeting string
}
```

**For the AI chatbot page.**

Simple but effective - just needs a greeting like "Hello! How can I help you explore Kosovo?"

---

### 11. PageBundle (Lines 155-159) ⭐ IMPORTANT!

```go
type PageBundle struct {
	PageName    string
	Data        interface{}
	CurrentUser User
}
```

**🤔 This is the MASTER wrapper that unifies all page data!**

**The problem without PageBundle:**
```go
// Every page has different data type
adminHandler(AdminPageData{...})
dashboardHandler(DashboardPageData{...})
messageHandler(MessagePageData{...})

// renderTemplate would need to accept ANY type
func renderTemplate(w http.ResponseWriter, name string, data ???) {
	// What type is data?
}
```

**The solution with PageBundle:**
```go
// All pages use same wrapper
renderTemplate(w, "admin", PageBundle{
	PageName: "admin",
	Data: AdminPageData{...},
	CurrentUser: user,
})

renderTemplate(w, "dashboard", PageBundle{
	PageName: "dashboard",
	Data: DashboardPageData{...},
	CurrentUser: user,
})

// renderTemplate signature is simple
func renderTemplate(w http.ResponseWriter, name string, data PageBundle) {
	// Always receives PageBundle
}
```

**🤔 What's `interface{}`?**

```go
Data interface{}
```

`interface{}` is a special type that means "any type at all" - like a universal container.

```go
var box interface{}

box = 42                    // ✅ Can hold int
box = "hello"               // ✅ Can hold string
box = []int{1, 2, 3}        // ✅ Can hold slice
box = AdminPageData{...}    // ✅ Can hold struct
box = anything              // ✅ Literally anything!
```

**Why use it in PageBundle?**

Each page needs different data:
- Admin page → `AdminPageData`
- Dashboard → `DashboardPageData`
- Message → `MessagePageData`

`interface{}` lets `Data` be any of these!

**In the template (Lines 1195-1198):**
```go
func renderTemplate(w http.ResponseWriter, tmplName string, data PageBundle) {
	err := tpl.ExecuteTemplate(w, tmplName, data)
	// Template receives the PageBundle
}
```

**Template can access:**
```html
<!-- PageBundle fields -->
Current user: {{.CurrentUser.Username}}
Page name: {{.PageName}}

<!-- The specific page data inside .Data -->
{{if .Data.Message}}
	<p>{{.Data.Message}}</p>
{{end}}

{{range .Data.Users}}
	<li>{{.Username}}</li>
{{end}}
```

---

## 🌐 PART 3: API Models

These structs handle JSON APIs (AJAX requests from JavaScript and communication with Gemini AI).

### 12. AIChatRequest (Lines 161-163)

```go
type AIChatRequest struct {
	Prompt string `json:"prompt"`
}
```

**What JavaScript sends when user types in the chatbot.**

**JavaScript code:**
```javascript
fetch('/api/chat', {
	method: 'POST',
	headers: {'Content-Type': 'application/json'},
	body: JSON.stringify({
		prompt: "I want to see castles"
	})
})
```

**Go receives it (Lines 998-1001):**
```go
func chatAPIHandler(w http.ResponseWriter, r *http.Request) {
	var req AIChatRequest
	json.NewDecoder(r.Body).Decode(&req)
	// Now req.Prompt = "I want to see castles"
}
```

**The flow:**
```
Browser JavaScript → JSON: {"prompt": "I want to see castles"}
                              ↓
Go `json.Decoder` → Fills AIChatRequest struct
                              ↓
Your handler → Access: req.Prompt
```

---

### 13. AIChatResponse (Lines 165-168)

```go
type AIChatResponse struct {
	Type    string      `json:"type"`
	Content interface{} `json:"content,omitempty"`
}
```

**What Go sends back to JavaScript.**

**Three response types:**

**1. Places search response:**
```go
AIChatResponse{
	Type: "places",
	Content: map[string]string{
		"keyword":  "castle",
		"category": "Historical",
	},
}
```
JSON: `{"type": "places", "content": {"keyword": "castle", "category": "Historical"}}`

**2. Counseling response:**
```go
AIChatResponse{
	Type: "counseling",
}
```
JSON: `{"type": "counseling"}`

**3. Other response:**
```go
AIChatResponse{
	Type: "other",
}
```
JSON: `{"type": "other"}`

**🤔 What's `omitempty`?**

```go
Content interface{} `json:"content,omitempty"`
                                    ↑↑↑↑↑↑↑↑
```

If `Content` is `nil`, omit it from JSON entirely:

**Without omitempty:**
```json
{"type": "other", "content": null}
```

**With omitempty:**
```json
{"type": "other"}
```

Cleaner and smaller JSON!

---

### 14-17. Gemini API Models (Lines 170-195)

These match Google's Gemini AI API structure exactly.

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

**🤔 Why so nested and complex?**

This is **Google's API format**, not your choice! You must match their exact JSON structure.

**Building a request (Lines 1102-1110):**
```go
geminiReq := GeminiRequest{
	Contents: []GeminiContent{
		{
			Parts: []GeminiPart{
				{Text: aiSystemPrompt + "\n\nUser: " + userPrompt},
			},
		},
	},
}

jsonData, _ := json.Marshal(geminiReq)
```

**Creates this JSON:**
```json
{
  "contents": [
    {
      "parts": [
        {
          "text": "You are a classification bot...\n\nUser: I want to see castles"
        }
      ]
    }
  ]
}
```

**Receiving Gemini's response (Lines 1128-1137):**
```go
var geminiResp GeminiResponse
json.NewDecoder(resp.Body).Decode(&geminiResp)

// Check for API errors
if geminiResp.Error != nil {
	log.Printf("Gemini error: %s", geminiResp.Error.Message)
	return "", fmt.Errorf("AI error")
}

// Extract the classification
text := geminiResp.Candidates[0].Content.Parts[0].Text
```

**Gemini responds with:**
```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "places"
          }
        ]
      }
    }
  ]
}
```

**🤔 What's `*struct` in the Error field?**

```go
Error *struct {
	Message string `json:"message"`
}
```

The `*` means **pointer**. This field can be:
- `nil` (no error - everything OK)
- A pointer to a struct (error occurred)

**Checking for errors:**
```go
if geminiResp.Error != nil {
	// Error exists!
	fmt.Println("Error:", geminiResp.Error.Message)
} else {
	// No error, success!
}
```

---

## 🧩 How Structs Work Together - Real Example

**Scenario: User submits a new place**

```
Step 1: Browser sends JSON
{
  "title": "Visoki Decani",
  "category": "Religious",
  "description": "UNESCO World Heritage monastery",
  "googleMapsLink": "https://..."
}

Step 2: Go handler receives and creates Place struct
func submitPlaceHandler(w http.ResponseWriter, r *http.Request) {
	place := Place{
		Title:             r.FormValue("title"),
		Category:          r.FormValue("category"),
		Description:       r.FormValue("description"),
		GoogleMapsLink:    r.FormValue("googleMapsLink"),
		SubmittedByUserID: user.ID,
		IsApproved:        false,  // Needs admin approval
	}

	// Save to database
	db.Exec("INSERT INTO places (...) VALUES (...)")
}

Step 3: Admin views pending places
func adminPlacesHandler(w http.ResponseWriter, r *http.Request) {
	// Get pending places
	var pendingPlaces []Place
	rows.Scan into Place structs...

	// Render admin page
	renderTemplate(w, "admin_places", PageBundle{
		Data: AdminPlacesPageData{
			PendingPlaces: pendingPlaces,  // Slice of Place structs
		},
	})
}

Step 4: Admin approves
func adminPlacesHandler(w http.ResponseWriter, r *http.Request) {
	if action == "approve" {
		db.Exec("UPDATE places SET is_approved = TRUE WHERE id = ?", placeID)
	}
}

Step 5: Now visible in public places list
func placesAPIHandler(w http.ResponseWriter, r *http.Request) {
	var places []Place
	db.Query("SELECT * FROM places WHERE is_approved = TRUE")

	// Send as JSON to browser
	json.NewEncoder(w).Encode(places)
}
```

---

## 🎓 Advanced Struct Concepts

### 1. Methods on Structs

You can add functions to structs:

```go
// Add a method to User
func (u User) IsActive() bool {
	return u.IsVerified && !u.IsAdmin
}

// Usage:
user := User{IsVerified: true, IsAdmin: false}
if user.IsActive() {
	fmt.Println("Active regular user!")
}
```

Your code doesn't use methods (yet), but you could add them!

### 2. Struct Embedding

```go
type Animal struct {
	Name string
	Age  int
}

type Dog struct {
	Animal  // Embedded - Dog "inherits" Animal fields
	Breed string
}

dog := Dog{
	Animal: Animal{Name: "Buddy", Age: 5},
	Breed: "Golden Retriever",
}

// Can access embedded fields directly
fmt.Println(dog.Name)   // "Buddy" (from Animal)
fmt.Println(dog.Breed)  // "Golden Retriever"
```

### 3. Pointers vs Values

**Passing by value (copy):**
```go
func updateUser(u User) {
	u.Username = "new_name"
	// Only changes the COPY, not the original!
}

user := User{Username: "old_name"}
updateUser(user)
fmt.Println(user.Username)  // Still "old_name"
```

**Passing by pointer (reference):**
```go
func updateUser(u *User) {
	u.Username = "new_name"
	// Changes the ACTUAL user!
}

user := User{Username: "old_name"}
updateUser(&user)  // Pass address with &
fmt.Println(user.Username)  // Now "new_name"!
```

**Your code uses pointers for database Scan (Line 341):**
```go
db.QueryRow(...).Scan(&user.ID, &user.Username, ...)
//                     ↑ Address of fields, so Scan can modify them
```

---

## 📊 Complete Struct Summary

| Struct | Lines | Purpose | Key Fields |
|--------|-------|---------|------------|
| `User` | 74-83 | User account | ID, Username, Email, PasswordHash |
| `Place` | 86-99 | Tourist location | Title, Category, Coordinates, IsApproved |
| `Comment` | 102-110 | User comment | PlaceID, UserID, Content |
| `AdminPageData` | 114-120 | Admin panel | Users list, PendingCount |
| `AdminPlacesPageData` | 122-127 | Place approval | PendingPlaces |
| `DashboardPageData` | 129-131 | User dashboard | CurrentUser |
| `MessagePageData` | 133-136 | Info pages | Title, Message |
| `PlacesListPageData` | 138-143 | Browse places | Places, SearchQuery, Category |
| `PlaceDetailPageData` | 145-149 | Single place | Place, Comments |
| `ChatPageData` | 151-153 | AI chat | Greeting |
| `PageBundle` | 155-159 | Page wrapper | PageName, Data (any type), CurrentUser |
| `AIChatRequest` | 161-163 | Chat input | Prompt |
| `AIChatResponse` | 165-168 | Chat output | Type, Content |
| `GeminiRequest` | 170-178 | Gemini input | Contents structure |
| `GeminiResponse` | 180-195 | Gemini output | Candidates, Error |

---

## 🎯 Practice Exercise

**Design a rating system!**

Create structs for users to rate places with 1-5 stars.

**What you need:**

1. **Rating struct** - Store individual ratings
2. **Update PlaceDetailPageData** - Show ratings on place page
3. **Update Place struct** - Add average rating

**Try it yourself first, then check the answer below!**

<details>
<summary>Click to see solution</summary>

```go
// 1. Rating struct
type Rating struct {
	ID        int
	PlaceID   int
	UserID    int
	Stars     int       // 1-5
	CreatedAt time.Time
}

// 2. Modified PlaceDetailPageData
type PlaceDetailPageData struct {
	Place        Place
	Comments     []Comment
	Ratings      []Rating  // ← New!
	AverageStars float64   // ← New!
	CurrentUser  User
}

// 3. Modified Place struct (add this field)
type Place struct {
	// ... existing fields ...
	AverageRating float64 `json:"AverageRating"`  // ← New!
}

// Usage in handler:
func placeDetailHandler(w http.ResponseWriter, r *http.Request) {
	// Get ratings
	rows, _ := db.Query(`
		SELECT id, place_id, user_id, stars, created_at
		FROM ratings WHERE place_id = ?
	`, placeID)

	var ratings []Rating
	var totalStars int
	for rows.Next() {
		var rating Rating
		rows.Scan(&rating.ID, &rating.PlaceID, &rating.UserID,
		          &rating.Stars, &rating.CreatedAt)
		ratings = append(ratings, rating)
		totalStars += rating.Stars
	}

	// Calculate average
	averageStars := 0.0
	if len(ratings) > 0 {
		averageStars = float64(totalStars) / float64(len(ratings))
	}

	// Render with ratings
	renderTemplate(w, "place_detail", PageBundle{
		Data: PlaceDetailPageData{
			Place:        place,
			Comments:     comments,
			Ratings:      ratings,
			AverageStars: averageStars,
			CurrentUser:  user,
		},
	})
}
```

</details>

---

## 💡 Key Takeaways

✅ **Structs are blueprints** - Define custom data types
✅ **Fields have types** - Go checks you use correct data
✅ **Struct tags control JSON** - `` `json:"fieldName"` ``
✅ **sql.Null types** - For fields that can be NULL in database
✅ **interface{}** - Can hold any type (used in PageBundle)
✅ **PageBundle unifies pages** - Consistent structure for all pages
✅ **Nested structs** - Like Gemini models (match external APIs)
✅ **Pointers with &** - Pass address so functions can modify

---

## 🚀 Next Steps

Now you understand how your data is organized! Next, let's see how it's stored and retrieved from the database.

**Next chapter:** [Database Operations](05-database-operations.md)
Learn how structs become database rows and vice versa!

---

**Remember:** Structs are the skeleton of your app - they define what data looks like and how it flows through your program! 🏗️

---

*Happy coding! Next up: Database magic* 🏗️➡️💾
