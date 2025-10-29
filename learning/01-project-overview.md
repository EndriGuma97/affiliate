# Chapter 1: Project Overview - Kosovo Explorer

## Welcome to Your Learning Journey!

This guide will help you understand every aspect of your Go web application. We'll start with a high-level overview and gradually dive deep into each component.

---

## What Is This Application?

**Kosovo Explorer** is a full-stack web application built entirely in Go. It's a community-driven platform where users can:

- **Discover** interesting places in Kosovo on an interactive map
- **Submit** new locations for others to explore
- **Comment** on places they've visited
- **Interact** with an AI assistant powered by Google's Gemini API
- **Manage** content through an admin panel

Think of it as a combination of:
- A social travel guide (like TripAdvisor)
- An interactive map platform (like Google Maps)
- A community forum
- An AI-powered assistant

---

## Application Architecture: The Big Picture

### 1. **Single-File Monolithic Design**

Your entire application lives in one file: `main.go`. While this might seem unusual, it's actually common for smaller Go applications. Here's why:

**Advantages:**
- Easy to understand the entire application flow
- No need to jump between multiple files
- Simple deployment (just one executable)

**When to split:**
- When the file exceeds ~2000-3000 lines
- When you have distinct, reusable packages
- When working with a team

### 2. **Technology Stack**

```
┌─────────────────────────────────────────┐
│         User's Web Browser              │
│  (HTML, CSS, JavaScript, Leaflet Maps)  │
└──────────────┬──────────────────────────┘
               │ HTTP Requests
┌──────────────▼──────────────────────────┐
│         Go Web Server                   │
│  - HTTP Routing (net/http)             │
│  - Session Management (gorilla)         │
│  - Template Rendering (html/template)   │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼──────┐      ┌──────▼──────────┐
│ SQLite DB│      │  Gemini AI API  │
│ (users.db)│      │  (External)     │
└──────────┘      └─────────────────┘
```

**Frontend:**
- HTML/CSS embedded in Go templates
- Leaflet.js for interactive maps
- Vanilla JavaScript for dynamic features

**Backend:**
- Go standard library (`net/http` for web server)
- Gorilla Sessions for user login management
- SQLite for data persistence

**External Services:**
- Google Gemini AI for chatbot functionality
- SMTP server for sending verification emails

### 3. **Key Features Breakdown**

| Feature | What It Does | Where In Code |
|---------|-------------|---------------|
| **User Registration** | Creates accounts with email verification | `registerHandler` (line 390) |
| **Authentication** | Secure login with password hashing | `loginHandler` (line 451) |
| **Session Management** | Keeps users logged in | `getCurrentUser` (line 331) |
| **Place Submissions** | Users submit locations | `submitPlaceHandler` (line 866) |
| **Admin Approval** | Admins review submissions | `adminPlacesHandler` (line 632) |
| **Interactive Map** | Shows places on Leaflet map | `mapHandler` + JS (line 720) |
| **Commenting System** | Users discuss places | `commentHandler` (line 911) |
| **AI Chatbot** | Gemini-powered assistant | `chatAPIHandler` (line 961) |

---

## How Data Flows Through The Application

### Example: A User Registers an Account

```
1. User fills registration form in browser
      ↓
2. Browser sends POST request to /register
      ↓
3. registerHandler function receives request
      ↓
4. Password is hashed using bcrypt
      ↓
5. Verification token is generated
      ↓
6. User data is inserted into SQLite database
      ↓
7. Verification email is sent via SMTP
      ↓
8. User receives email, clicks link
      ↓
9. verifyHandler marks account as verified
      ↓
10. User can now log in
```

### Example: Displaying the Map

```
1. User navigates to /map
      ↓
2. mapHandler renders HTML page with Leaflet
      ↓
3. JavaScript on page loads
      ↓
4. AJAX request to /api/places
      ↓
5. placesAPIHandler queries database
      ↓
6. Returns JSON array of approved places
      ↓
7. JavaScript creates markers on map
      ↓
8. User sees interactive map with pins
```

---

## Code Organization in main.go

Your file is structured in logical sections (marked with comments like `// --- SECTION ---`):

```go
// 1. CONFIGURATION (lines 24-38)
//    - API keys, SMTP settings, constants

// 2. GLOBALS (lines 40-45)
//    - Database connection, session store, templates

// 3. MODELS (lines 63-151)
//    - Structs defining data shapes (User, Place, Comment, etc.)

// 4. MAIN FUNCTION (lines 187-224)
//    - Application entry point
//    - Initializes database, sessions, templates
//    - Starts HTTP server

// 5. ROUTE SETUP (lines 226-254)
//    - Maps URLs to handler functions

// 6. DATABASE FUNCTIONS (lines 256-328)
//    - Creates tables, manages data

// 7. AUTHENTICATION (lines 330-379)
//    - Login validation, middleware

// 8. HANDLERS (lines 381-959)
//    - Functions that respond to HTTP requests

// 9. AI FUNCTIONS (lines 1044-1147)
//    - Gemini API integration

// 10. UTILITIES (lines 1149-1169)
//    - Helper functions (email, tokens, rendering)

// 11. TEMPLATES (lines 1171-2405)
//    - HTML templates as a giant string
```

This organization makes it easy to find specific functionality!

---

## Key Concepts You'll Learn

Throughout these chapters, you'll master:

1. **HTTP Web Servers** - How Go serves web pages
2. **Request/Response Cycle** - How browsers talk to servers
3. **Database Operations** - CRUD (Create, Read, Update, Delete)
4. **Security** - Password hashing, sessions, SQL injection prevention
5. **Templates** - Generating dynamic HTML
6. **JSON APIs** - Building endpoints for JavaScript
7. **Middleware** - Protecting routes with authentication
8. **External APIs** - Integrating with services like Gemini
9. **Concurrency** - How Go handles multiple users simultaneously

---

## What Makes Go Special For This Project?

### 1. **Simplicity**
Go's standard library includes everything needed for web development:
- `net/http` - Web server
- `database/sql` - Database access
- `html/template` - HTML generation
- `crypto/bcrypt` - Password security

No massive frameworks required!

### 2. **Performance**
Go compiles to native machine code, making it:
- Faster than interpreted languages (Python, Ruby)
- Lower memory usage
- Handles thousands of concurrent connections

### 3. **Concurrency**
The `net/http` package automatically handles each request in a separate **goroutine** (lightweight thread). This means:
- Multiple users can use the site simultaneously
- Database queries don't block other users
- No special configuration needed

### 4. **Single Binary Deployment**
When you compile this project:
```bash
go build main.go
```
You get a single executable file with NO dependencies. Just:
```bash
./main
```
And your entire web server is running!

---

## Next Steps

Now that you understand the big picture, we'll dive into each component:

- **Chapter 2:** Go fundamentals used in this code
- **Chapter 3:** Understanding imports and dependencies
- **Chapter 4:** Data models and structs
- **Chapter 5:** Database operations
- **And much more!**

Each chapter will reference specific line numbers in your `main.go` so you can follow along.

---

## Quick Reference: Line Number Guide

| Section | Lines | What's There |
|---------|-------|--------------|
| Configuration | 24-38 | API keys, URLs, constants |
| Global Variables | 40-45 | db, store, tpl |
| Data Models | 63-151 | User, Place, Comment structs |
| Main Function | 187-224 | Application startup |
| Database Init | 256-328 | Table creation, setup |
| Auth Helpers | 330-379 | Login checking, middleware |
| Public Routes | 382-538 | Home, register, login, verify |
| Protected Routes | 540-550 | Dashboard |
| Admin Routes | 552-717 | User/place management |
| Map & Places | 719-909 | Location features |
| Chat/AI | 940-1014 | Chatbot functionality |
| API Endpoints | 1016-1147 | JSON responses |
| Utilities | 1149-1169 | Helper functions |
| HTML Templates | 1171-2405 | Frontend code |

**Remember:** Use `Ctrl+G` in most editors to jump to a specific line number!

---

## Practice Exercise

Before moving to the next chapter, try this:

1. Open `main.go` in your editor
2. Find line 187 (the `main` function)
3. Read through lines 187-224
4. Try to identify:
   - Where the database is initialized
   - Where the HTTP server starts
   - What port the server listens on

**Answers:**
- Database init: line 191 (`initDB`)
- Server start: line 221 (`http.ListenAndServe`)
- Port: `:8080` (line 221)

---

**Ready for Chapter 2? Let's explore Go fundamentals in your code!**
