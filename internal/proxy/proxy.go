package proxy

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

// --- Database Model Definitions ---
type GatewayRoute struct {
	gorm.Model
	Prefix string `gorm:"uniqueIndex"`
	Target string
}

type ClientKey struct {
	gorm.Model
	KeyName string `gorm:"uniqueIndex"`
	Owner   string
}

// Engine encapsulates database and memory state
type Engine struct {
	DB           *gorm.DB
	routeCache   map[string][]string
	routeIndexes map[string]int
	indexMutex   sync.Mutex
	sortedKeys   []string
	cacheMutex   sync.RWMutex
	metrics      map[string]int
	metricsMutex sync.Mutex

	ipLimiters   map[string]*rate.Limiter
	limiterMutex sync.Mutex
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// NewEngine initializes the gateway engine
func NewEngine(db *gorm.DB) *Engine {
	e := &Engine{
		DB:           db,
		routeCache:   make(map[string][]string),
		routeIndexes: make(map[string]int),
		metrics:      make(map[string]int),
		ipLimiters:   make(map[string]*rate.Limiter),
	}
	e.DB.AutoMigrate(&GatewayRoute{}, &ClientKey{})
	e.initSeedData()
	e.ReloadRoutesCache()
	return e
}

// ReloadRoutesCache hot-reloads the memory cache
func (e *Engine) ReloadRoutesCache() {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	var routes []GatewayRoute
	e.DB.Find(&routes)

	e.routeCache = make(map[string][]string)
	e.routeIndexes = make(map[string]int)
	e.sortedKeys = []string{}

	for _, r := range routes {
		rawTargets := strings.Split(r.Target, ",")
		var cleanTargets []string
		for _, t := range rawTargets {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				cleanTargets = append(cleanTargets, trimmed)
			}
		}

		e.routeCache[r.Prefix] = cleanTargets
		e.routeIndexes[r.Prefix] = 0
		e.sortedKeys = append(e.sortedKeys, r.Prefix)
	}

	sort.Slice(e.sortedKeys, func(i, j int) bool {
		return len(e.sortedKeys[i]) > len(e.sortedKeys[j])
	})

	log.Printf("🔄 [Engine] Route cache hot-reloaded. Order: %v", e.sortedKeys)
}

// WithLogging handles auditing and latency metrics
func (e *Engine) WithLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		originalPath := r.URL.Path

		if strings.HasPrefix(originalPath, "/admin") {
			next(w, r)
			return
		}

		lrw := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next(lrw, r)
		latency := time.Since(startTime)

		log.Printf("[📊 AUDIT] %s │ %-6s │ %-3d │ %10v │ Path: %s",
			startTime.Format("2006-01-02 15:04:05"),
			r.Method,
			lrw.statusCode,
			latency,
			originalPath,
		)
	}
}

// WithCORS handles cross-origin configurations
func (e *Engine) WithCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-DigiRunner-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// WithAuth enforces dual-mode security checking
func (e *Engine) WithAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			next(w, r)
			return
		}

		var tokenStr string
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if tokenStr == "" {
			tokenStr = r.Header.Get("X-DigiRunner-Key")
		}

		if tokenStr == "" {
			http.Error(w, "🔒 Unauthorized: Missing credentials", http.StatusUnauthorized)
			return
		}

		if strings.Count(tokenStr, ".") == 2 {
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte("ncu-csie-secret-558"), nil
			})

			if err == nil && token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					owner := claims["sub"].(string)
					log.Printf("🔓 [JWT SUCCESS] Verified claims in-memory. User: %s", owner)
					next(w, r)
					return
				}
			}

			log.Printf("🔒 [AUTH DENIED] Invalid JWT signature: %v", err)
			http.Error(w, "🔒 Forbidden: Invalid or expired JWT", http.StatusForbidden)
			return
		}

		var clientKey ClientKey
		if err := e.DB.Where("key_name = ?", tokenStr).First(&clientKey).Error; err != nil {
			log.Printf("🔒 [AUTH DENIED] API Key not found in DB: %s", tokenStr)
			http.Error(w, "🔒 Forbidden: Invalid API Key", http.StatusForbidden)
			return
		}

		log.Printf("🔓 [API KEY SUCCESS] Validated key from DB. User: %s", clientKey.Owner)
		next(w, r)
	}
}

// ProxyHandler maps routes and relays incoming traffic
func (e *Engine) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	currentPath := r.URL.Path

	if strings.HasPrefix(currentPath, "/admin") {
		e.AdminHandler(w, r)
		return
	}

	e.cacheMutex.RLock()
	var targets []string
	var routePrefix string

	for _, prefix := range e.sortedKeys {
		if strings.HasPrefix(currentPath, prefix) {
			routePrefix = prefix
			targets = e.routeCache[prefix]
			break
		}
	}
	e.cacheMutex.RUnlock()

	if len(targets) == 0 {
		http.Error(w, "🚫 Go-digiRunner: API Route Not Registered", http.StatusNotFound)
		return
	}

	e.indexMutex.Lock()
	currentIndex := e.routeIndexes[routePrefix]
	targetURLStr := targets[currentIndex]

	e.routeIndexes[routePrefix] = (currentIndex + 1) % len(targets)
	e.indexMutex.Unlock()

	e.metricsMutex.Lock()
	e.metrics[routePrefix]++
	e.metricsMutex.Unlock()

	targetServer, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "Internal Gateway Error", http.StatusInternalServerError)
		return
	}

	r.URL.Path = strings.TrimPrefix(currentPath, routePrefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	log.Printf("[⚡️ Forwarding] %s -> %s%s", currentPath, targetURLStr, r.URL.Path)
	proxy := httputil.NewSingleHostReverseProxy(targetServer)
	r.Host = targetServer.Host

	r.Header.Del("Authorization")
	r.Header.Del("X-DigiRunner-Key")

	proxy.ServeHTTP(w, r)
}

// AdminHandler serves the web UI for real-time upsert management
func (e *Engine) AdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		idStr := r.FormValue("id")
		prefix := r.FormValue("prefix")
		target := r.FormValue("target")

		if prefix != "" && target != "" {
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}

			if idStr != "" {
				var route GatewayRoute
				if err := e.DB.First(&route, idStr).Error; err == nil {
					route.Prefix = prefix
					route.Target = target
					e.DB.Save(&route)
					log.Printf("✏️  [Control Plane] Updated route rule ID: %s (%s)", idStr, prefix)
				}
			} else {
				e.DB.Create(&GatewayRoute{Prefix: prefix, Target: target})
				log.Printf("➕ [Control Plane] Registered new route rule: %s", prefix)
			}
			e.ReloadRoutesCache()
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/admin/delete/") {
		id := strings.TrimPrefix(r.URL.Path, "/admin/delete/")
		e.DB.Delete(&GatewayRoute{}, id)
		e.ReloadRoutesCache()
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	type DisplayRoute struct {
		ID     uint
		Prefix string
		Target string
		Hits   int
	}

	var routes []GatewayRoute
	e.DB.Find(&routes)

	var displayList []DisplayRoute
	e.metricsMutex.Lock()
	for _, r := range routes {
		displayList = append(displayList, DisplayRoute{
			ID:     r.ID,
			Prefix: r.Prefix,
			Target: r.Target,
			Hits:   e.metrics[r.Prefix],
		})
	}
	e.metricsMutex.Unlock()

	var editRoute GatewayRoute
	isEditing := false
	editID := r.URL.Query().Get("edit")
	if editID != "" {
		if err := e.DB.First(&editRoute, editID).Error; err == nil {
			isEditing = true
		}
	}

	pageData := struct {
		Routes    []DisplayRoute
		EditRoute GatewayRoute
		IsEditing bool
	}{
		Routes:    displayList,
		EditRoute: editRoute,
		IsEditing: isEditing,
	}

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Go-digiRunner Admin Console</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
	</head>
	<body class="bg-light">
		<div class="container py-5">
			<div class="d-flex justify-content-between align-items-center mb-4">
				<h1 class="text-primary m-0">Pinecone Runner Gateway Console</h1>
			</div>
			
			<div class="card mb-4 shadow-sm border-{{if .IsEditing}}warning{{else}}dark{{end}}">
				<div class="card-header bg-{{if .IsEditing}}warning text-dark{{else}}dark text-white{{end}} fw-bold">
					{{if .IsEditing}}✏️ Edit API Routing Rule{{else}}➕ Register New API Route{{end}}
					{{if .IsEditing}}<a href="/admin" class="btn btn-sm btn-secondary float-end">Cancel</a>{{end}}
				</div>
				<div class="card-body">
					<form method="POST" action="/admin" class="row g-3">
						<input type="hidden" name="id" value="{{if .IsEditing}}{{.EditRoute.ID}}{{end}}">
						
						<div class="col-md-4">
							<label class="form-label fw-bold">Gateway Path (Prefix)</label>
							<input type="text" name="prefix" class="form-control" placeholder="e.g., /api" value="{{if .IsEditing}}{{.EditRoute.Prefix}}{{end}}" required>
						</div>
						<div class="col-md-6">
							<label class="form-label fw-bold">Backend Targets (Separated by " , " for load balancing)</label>
							<input type="text" name="target" class="form-control" placeholder="e.g., http://127.0.0.1:8081, http://127.0.0.1:8082" value="{{if .IsEditing}}{{.EditRoute.Target}}{{end}}" required>
						</div>
						<div class="col-md-2 d-flex align-items-end">
							<button type="submit" class="btn btn-{{if .IsEditing}}warning{{else}}success{{end}} w-100 fw-bold">
								{{if .IsEditing}}Save Changes{{else}}Deploy{{end}}
							</button>
						</div>
					</form>
				</div>
			</div>

			<div class="card shadow-sm">
				<div class="card-header bg-secondary text-white fw-bold">📋 Active API Routing Table (Longest Prefix Match First)</div>
				<div class="card-body p-0">
					<table class="table table-striped table-hover m-0 align-middle">
						<thead class="table-dark">
							<tr>
								<th style="width: 8%">ID</th>
								<th style="width: 25%">Gateway Prefix</th>
								<th style="width: 40%">Backend Upstream Targets</th>
								<th style="width: 12%">Request Hits</th>
								<th style="width: 15%">Actions</th>
							</tr>
						</thead>
						<tbody>
							{{range .Routes}}
							<tr>
								<td>{{.ID}}</td>
								<td><code>{{.Prefix}}</code></td>
								<td><small class="text-muted">{{.Target}}</small></td>
								<td>
									<span class="badge bg-{{if gt .Hits 0}}primary{{else}}secondary{{end}} fs-6">
										{{.Hits}} hits
									</span>
								</td>
								<td>
									<a href="/admin?edit={{.ID}}" class="btn btn-outline-warning btn-sm me-1">Edit</a>
									<a href="/admin/delete/{{.ID}}" class="btn btn-outline-danger btn-sm">Delete</a>
								</td>
							</tr>
							{{end}}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	</body>
	</html>`

	t, _ := template.New("admin").Parse(tmpl)
	t.Execute(w, pageData)
}

func (e *Engine) initSeedData() {
	var count int64
	e.DB.Model(&GatewayRoute{}).Count(&count)
	if count == 0 {
		e.DB.Create(&GatewayRoute{Prefix: "/service-a", Target: "https://jsonplaceholder.typicode.com"})
		e.DB.Create(&GatewayRoute{Prefix: "/service-b", Target: "https://api.github.com"})
	}
	e.DB.Model(&ClientKey{}).Count(&count)
	if count == 0 {
		e.DB.Create(&ClientKey{KeyName: "admin-pass-558", Owner: "NCU_CSIE_Admin"})
	}
}

// WithRateLimit enforces sliding/bucket throttling policies
func (e *Engine) WithRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			next(w, r)
			return
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		e.limiterMutex.Lock()
		limiter, exists := e.ipLimiters[ip]
		if !exists {
			limiter = rate.NewLimiter(2, 3)
			e.ipLimiters[ip] = limiter
		}
		e.limiterMutex.Unlock()

		if !limiter.Allow() {
			log.Printf("⚠️  [RATE LIMIT] Throttling connection from IP: %s", ip)
			http.Error(w, "🛑 Too Many Requests: Rate limit exceeded (429)", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
