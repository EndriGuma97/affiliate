# Chapter 6: HTTP Routing and Handlers

## Introduction

Your web server uses the **net/http** package to route URLs to handler functions. When a user visits `/login`, Go calls `loginHandler`. This chapter explains how it all works!

---

## HTTP Basics Refresher

### The Request-Response Cycle

```
Browser                          Server
   │                                │
   │─── GET /places ────────────────→│
   │                                │
   │                            Process request
   │                            Query database
   │                            Generate HTML
   │                                │
   │←──── HTML Response ────────────│
   │                                │
```

### HTTP Methods

| Method | Purpose | Example in Your App |
|--------|---------|---------------------|
| GET | Retrieve data | View places, home page |
| POST | Submit data | Login, register, submit place |
| PUT | Update resource | (not used) |
| DELETE | Remove resource | (not used via method, uses POST with action) |

---

## Section 1: The Main Function Setup (Lines 187-224)

### Initialization Sequence

```go
func main() {
    var err error

    // 1. Initialize Database
    db, err = initDB("./users.db")
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    log.Println("Database initialized and tables created.")

    // 2. Initialize Session Store
    store = sessions.NewCookieStore([]byte(sessionKey))
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400 * 7, // 7 days
        HttpOnly: true,
    }

    // 3. Parse Templates
    tpl = template.Must(template.New("main").Funcs(template.FuncMap{
        "safeHTML": func(s string) template.HTML {
            return template.HTML(s)
        },
        "formatTime": func(t time.Time) string {
            return t.Format("Jan 2, 2006 at 3:04 PM")
        },
    }).Parse(allTemplates))

    // 4. Setup Routes
    mux := http.NewServeMux()
    setupRoutes(mux)

    // 5. Start Server
    log.Println("Starting server on " + baseURL + " ...")
    if err := http.ListenAndServe(":8080", mux); err != nil {
        log.Fatal("Failed to start server:", err)
    }
}
```

**Step-by-step:**

1. **Database** - Must be first (handlers need it)
2. **Sessions** - Configure cookie-based login
3. **Templates** - Parse all HTML templates once
4. **Routes** - Map URLs to handlers
5. **Start** - Begin listening for HTTP requests

### The ServeMux (Multiplexer)

```go
mux := http.NewServeMux()
```

**ServeMux** = URL router

Think of it as a phone switchboard:
```
User requests /login
    ↓
ServeMux checks routing table
    ↓
Routes to loginHandler
    ↓
Handler processes request
```

---

## Section 2: Route Setup (Lines 227-254)

```go
func setupRoutes(mux *http.ServeMux) {
    // --- Static/Public Routes ---
    mux.HandleFunc("/", homeHandler)
    mux.HandleFunc("/register", registerHandler)
    mux.HandleFunc("/login", loginHandler)
    mux.HandleFunc("/logout", logoutHandler)
    mux.HandleFunc("/verify", verifyHandler)

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

    // --- Protected Routes ---
    mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))

    // --- Admin Routes ---
    mux.HandleFunc("/admin/", requireAdmin(adminHandler))
    mux.HandleFunc("/admin/places", requireAdmin(adminPlacesHandler))
}
```

### Route Types

**1. Static Routes (Exact match)**
```go
mux.HandleFunc("/login", loginHandler)
```
Matches ONLY `/login`

**2. Prefix Routes (Trailing slash)**
```go
mux.HandleFunc("/place/", placeDetailHandler)
```
Matches:
- `/place/1`
- `/place/42`
- `/place/anything`

**3. Protected Routes (With middleware)**
```go
mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
```
Wraps handler in authentication check

### URL Patterns Visualization

```
/                    → homeHandler (homepage)
/login               → loginHandler (login form)
/register            → registerHandler (signup form)
/logout              → logoutHandler (logout action)
/verify?token=xxx    → verifyHandler (email verification)

/map                 → mapHandler (interactive map)
/places              → placesHandler (list all places)
/place/42            → placeDetailHandler (specific place)
/chat                → chatPageHandler (AI chatbot)

/api/chat            → chatAPIHandler (JSON API)
/api/places          → placesAPIHandler (JSON API)
/api/places/submit   → submitPlaceHandler (submit new place)
/api/comment         → commentHandler (add comment) [PROTECTED]

/dashboard           → dashboardHandler [PROTECTED]
/admin/              → adminHandler [ADMIN ONLY]
/admin/places        → adminPlacesHandler [ADMIN ONLY]
```

---

## Section 3: Handler Function Anatomy

### Basic Handler Structure

```go
func handlerName(w http.ResponseWriter, r *http.Request) {
    // w = response writer (send data back to browser)
    // r = request (data from browser)
}
```

**Parameters:**

**`http.ResponseWriter`** - Write response to client
```go
w.Write([]byte("Hello"))           // Write bytes
fmt.Fprintf(w, "Hello %s", name)   // Formatted output
http.Error(w, "Error", 500)        // Send error
http.Redirect(w, r, "/", 303)      // Redirect
```

**`*http.Request`** - Read request data
```go
r.Method               // "GET", "POST", etc.
r.URL.Path             // "/login"
r.FormValue("username") // Form field value
r.URL.Query().Get("q") // URL parameter ?q=search
```

---

## Section 4: Example Handlers Explained

### Example 1: Home Handler (Lines 382-388)

```go
func homeHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := getCurrentUser(r)
    renderTemplate(w, "home", PageBundle{
        PageName:    "home",
        CurrentUser: user,
    })
}
```

**Flow:**
1. Try to get current user (if logged in)
2. Render "home" template
3. Pass user data (for navbar customization)

**Simple handler** - Just display a page!

### Example 2: Login Handler (Lines 451-486)

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // GET request: Show login form
    if r.Method == http.MethodGet {
        user, _ := getCurrentUser(r)
        renderTemplate(w, "login", PageBundle{
            CurrentUser: user,
        })
        return
    }

    // POST request: Process login
    username := r.FormValue("username")
    password := r.FormValue("password")

    var user User
    err := db.QueryRow(
        "SELECT id, username, email, password_hash, is_verified, is_admin FROM users WHERE username = ? OR email = ?",
        username, username,
    ).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsAdmin)

    // Check password
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

**Handles TWO scenarios:**

**GET (Display form):**
```
Browser → GET /login → Show login page
```

**POST (Process login):**
```
Browser → POST /login (username, password)
    ↓
Query database for user
    ↓
Verify password with bcrypt
    ↓
If valid: Create session → Redirect to dashboard
If invalid: Show error message
```

**Key concepts:**

**1. Method checking:**
```go
if r.Method == http.MethodGet {
    // Show form
    return
}
// Handle POST (implicit else)
```

**2. Form values:**
```go
username := r.FormValue("username")
```
Gets value from form field with `name="username"`

**3. Session creation:**
```go
session.Values["user_id"] = user.ID  // Store user ID
session.Save(r, w)                    // Send cookie to browser
```

**4. Redirect:**
```go
http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```
- 303 status code (See Other)
- Browser navigates to /dashboard

### Example 3: Places List Handler (Lines 728-800)

```go
func placesHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := getCurrentUser(r)

    // Get query parameters
    searchQuery := r.URL.Query().Get("q")
    category := r.URL.Query().Get("category")

    var places []Place
    var rows *sql.Rows
    var err error

    // Build query based on filters
    query := `
        SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
               p.google_maps_link, p.created_at, u.username,
               (SELECT COUNT(*) FROM comments WHERE place_id = p.id) as comment_count
        FROM places p
        JOIN users u ON p.submitted_by_user_id = u.id
        WHERE p.is_approved = TRUE`

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

    rows, err = db.Query(query, args...)
    if err != nil {
        // Handle error, render empty results
    }
    defer rows.Close()

    // Fetch all places
    for rows.Next() {
        var p Place
        rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
            &p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername, &p.CommentCount)
        places = append(places, p)
    }

    // Render template with data
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

**Features:**

**1. URL parameters:**
```
/places?q=restaurant&category=Restaurant
         ↓
searchQuery = "restaurant"
category = "Restaurant"
```

**2. Dynamic query building:**
- No filters: Show all places
- Search only: Filter by title/description
- Category only: Filter by category
- Both: Apply both filters

**3. Complex data passing:**
```go
Data: PlacesListPageData{
    Places:       []Place{...},  // Array of places
    SearchQuery:  "restaurant",   // What user searched
    Category:     "Restaurant",   // Selected category
    TotalMatches: 15,             // Count of results
}
```

Template can display: "Found 15 places matching 'restaurant'"

---

## Section 5: API Handlers (JSON Responses)

### Example: Places API Handler (Lines 1016-1042)

```go
func placesAPIHandler(w http.ResponseWriter, r *http.Request) {
    // Get approved places for the map
    rows, err := db.Query(`
        SELECT p.id, p.title, p.description, p.category, p.latitude, p.longitude,
               p.google_maps_link, p.created_at, u.username
        FROM places p
        JOIN users u ON p.submitted_by_user_id = u.id
        WHERE p.is_approved = TRUE AND p.latitude != 0 AND p.longitude != 0
        ORDER BY p.created_at DESC
    `)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var places []Place
    for rows.Next() {
        var p Place
        rows.Scan(&p.ID, &p.Title, &p.Description, &p.Category, &p.Latitude,
            &p.Longitude, &p.GoogleMapsLink, &p.CreatedAt, &p.SubmittedByUsername)
        places = append(places, p)
    }

    // Send JSON response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(places)
}
```

**Key differences from HTML handlers:**

**1. Sets JSON content type:**
```go
w.Header().Set("Content-Type", "application/json")
```
Tells browser to expect JSON

**2. Encodes struct as JSON:**
```go
json.NewEncoder(w).Encode(places)
```

**Output:**
```json
[
    {
        "ID": 1,
        "Title": "Prizren Castle",
        "Description": "Historic fortress...",
        "Category": "Culture",
        "Latitude": 42.6026,
        "Longitude": 20.9030,
        ...
    },
    {
        "ID": 2,
        "Title": "Sunset Cafe",
        ...
    }
]
```

**3. JavaScript fetches this:**
```javascript
fetch('/api/places')
    .then(res => res.json())
    .then(places => {
        // Display places on map
    });
```

---

## Section 6: Form Handling

### Reading Form Data

**HTML form:**
```html
<form method="POST" action="/register">
    <input type="text" name="username">
    <input type="email" name="email">
    <input type="password" name="password">
    <button type="submit">Sign Up</button>
</form>
```

**Go handler:**
```go
func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodGet {
        // Show form
        return
    }

    // Read form values
    username := r.FormValue("username")
    email := r.FormValue("email")
    password := r.FormValue("password")

    // Process registration...
}
```

**`r.FormValue()`** automatically:
- Parses POST body
- Gets value by field name
- Returns empty string if not present

---

## Section 7: Redirects

### Types of Redirects

**1. After successful action (303 See Other):**
```go
http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```
Used after POST to prevent duplicate submissions

**2. Not found (404):**
```go
http.NotFound(w, r)
```

**3. Unauthorized (401):**
```go
http.Error(w, "Unauthorized", http.StatusUnauthorized)
```

### Post-Redirect-Get (PRG) Pattern

```
User submits form (POST)
    ↓
Server processes data
    ↓
Redirect to success page (GET)
    ↓
User sees success message
    ↓
User refreshes page → Safe! (GET is idempotent)
```

**Without PRG:**
```
User submits form
    ↓
Server shows success on same page
    ↓
User refreshes → Resubmits form! → Duplicate data!
```

**Your code uses PRG (line 588):**
```go
// Store message in session
session.Values["admin_message"] = message
session.Save(r, w)
http.Redirect(w, r, "/admin/", http.StatusSeeOther)
```

---

## Section 8: Error Handling in Handlers

### Common Patterns

**1. Database errors:**
```go
rows, err := db.Query(...)
if err != nil {
    http.Error(w, "Database error", http.StatusInternalServerError)
    return
}
```

**2. Not found:**
```go
err := db.QueryRow(...).Scan(...)
if err != nil {
    http.NotFound(w, r)
    return
}
```

**3. User-facing errors:**
```go
renderTemplate(w, "login", PageBundle{
    Data: MessagePageData{
        Title:   "Login Failed",
        Message: "Invalid username or password.",
    },
})
```

---

## Section 9: Handler Best Practices

### ✅ What Your Code Does Well

1. **Separates GET and POST logic**
   ```go
   if r.Method == http.MethodGet {
       // Show form
       return
   }
   // Handle POST
   ```

2. **Checks authentication before protected actions**
   ```go
   user, err := getCurrentUser(r)
   if err != nil {
       http.Redirect(w, r, "/login", http.StatusSeeOther)
       return
   }
   ```

3. **Uses Post-Redirect-Get pattern**
   ```go
   // Process form
   // Store success message in session
   http.Redirect(w, r, "/success-page", http.StatusSeeOther)
   ```

4. **Validates input**
   ```go
   if title == "" || category == "" {
       http.Error(w, "Missing required fields", http.StatusBadRequest)
       return
   }
   ```

### ⚠️ Potential Improvements

1. **Input sanitization**
   ```go
   // Add validation
   if len(username) < 3 || len(username) > 20 {
       // Error: invalid length
   }
   ```

2. **Rate limiting** (prevent spam)
3. **CSRF protection** (prevent cross-site request forgery)
4. **Request logging** (for debugging)

---

## Practice Exercises

### Exercise 1: Add a New Route

Create a route `/about` that shows an about page:

**Solution:**
```go
// In setupRoutes:
mux.HandleFunc("/about", aboutHandler)

// Handler:
func aboutHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := getCurrentUser(r)
    renderTemplate(w, "about", PageBundle{
        PageName:    "about",
        CurrentUser: user,
    })
}
```

### Exercise 2: Extract URL Path Parameter

Get the place ID from `/place/42`:

**Solution:**
```go
func placeDetailHandler(w http.ResponseWriter, r *http.Request) {
    pathParts := strings.Split(r.URL.Path, "/")
    // pathParts = ["", "place", "42"]

    if len(pathParts) < 3 {
        http.NotFound(w, r)
        return
    }

    placeID, err := strconv.Atoi(pathParts[2])
    if err != nil {
        http.NotFound(w, r)
        return
    }

    // Use placeID...
}
```

---

## Key Takeaways

✅ **ServeMux** - Routes URLs to handlers
✅ **Handler signature** - `func(w http.ResponseWriter, r *http.Request)`
✅ **w** - Write response back to client
✅ **r** - Read request data (method, form values, URL params)
✅ **Method checking** - Handle GET and POST differently
✅ **Redirects** - Use Post-Redirect-Get pattern
✅ **API handlers** - Return JSON instead of HTML
✅ **Error handling** - Graceful degradation

---

**Next Chapter:** Authentication and sessions - keeping users logged in!
