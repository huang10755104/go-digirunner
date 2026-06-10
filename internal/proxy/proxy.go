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

// --- 資料庫模型定義 ---
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

// Engine 網關核心引擎
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

// NewEngine 初始化網關引擎
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

// ReloadRoutesCache 熱加載快取
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

	log.Printf("🔄 [Engine] 路由快取熱加載完成。優先級: %v", e.sortedKeys)
}

// WithLogging 訪問日誌與效能監控中間件
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

		log.Printf("[📊 網關審計] %s │ %-6s │ %-3d │ %10v │ 入口路徑: %s",
			startTime.Format("2006-01-02 15:04:05"),
			r.Method,
			lrw.statusCode,
			latency,
			originalPath,
		)
	}
}

// WithCORS 跨網域處理中間件
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

// WithAuth 資安驗證中間件
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
			http.Error(w, "🔒 Unauthorized: 缺少認證憑證", http.StatusUnauthorized)
			return
		}

		if strings.Count(tokenStr, ".") == 2 {
			var jwtSecret = []byte("ncu-csie-secret-558")
			_ = jwtSecret

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte("ncu-csie-secret-558"), nil
			})

			if err == nil && token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					owner := claims["sub"].(string)
					log.Printf("🔓 [JWT 驗證成功] 歡迎 JWT 用戶: %s", owner)
					next(w, r)
					return
				}
			}

			log.Printf("🔒 [資安攔截] JWT 驗證失敗: %v", err)
			http.Error(w, "🔒 Forbidden: JWT 簽章無效或已過期", http.StatusForbidden)
			return
		}

		var clientKey ClientKey
		if err := e.DB.Where("key_name = ?", tokenStr).First(&clientKey).Error; err != nil {
			log.Printf("🔒 [資安攔截] 傳統 API Key 查無此人: %s", tokenStr)
			http.Error(w, "🔒 Forbidden: 憑證無效", http.StatusForbidden)
			return
		}

		log.Printf("🔓 [API Key 驗證成功] 歡迎老用戶: %s", clientKey.Owner)
		next(w, r)
	}
}

// ProxyHandler 核心轉發與控制台路由分配
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
		http.Error(w, "🚫 Go-digiRunner: 未註冊該 API 路由", http.StatusNotFound)
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
		http.Error(w, "網關內部錯誤", http.StatusInternalServerError)
		return
	}

	r.URL.Path = strings.TrimPrefix(currentPath, routePrefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	log.Printf("[⚡️無痛轉發] %s -> %s%s", currentPath, targetURLStr, r.URL.Path)
	proxy := httputil.NewSingleHostReverseProxy(targetServer)
	r.Host = targetServer.Host

	r.Header.Del("Authorization")
	r.Header.Del("X-DigiRunner-Key")

	proxy.ServeHTTP(w, r)
}

// AdminHandler 後台 GUI 邏輯 (支援動態 Upsert 編輯)
func (e *Engine) AdminHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 處理表單提交 (新增 或 更新)
	if r.Method == http.MethodPost {
		idStr := r.FormValue("id")
		prefix := r.FormValue("prefix")
		target := r.FormValue("target")

		if prefix != "" && target != "" {
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}

			if idStr != "" {
				// 🚀 【更新邏輯】：如果帶有隱藏 ID，代表是編輯現有資料
				var route GatewayRoute
				if err := e.DB.First(&route, idStr).Error; err == nil {
					route.Prefix = prefix
					route.Target = target
					e.DB.Save(&route)
					log.Printf("✏️  [控制面] 成功修改路由規則 ID: %s (%s)", idStr, prefix)
				}
			} else {
				// 🚀 【新增邏輯】：沒有 ID，建立新資料
				e.DB.Create(&GatewayRoute{Prefix: prefix, Target: target})
				log.Printf("➕ [控制面] 成功註冊新路由規則: %s", prefix)
			}
			e.ReloadRoutesCache() // 🔥 即時同步熱加載快取！
		}
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	// 2. 處理刪除路由
	if strings.HasPrefix(r.URL.Path, "/admin/delete/") {
		id := strings.TrimPrefix(r.URL.Path, "/admin/delete/")
		e.DB.Delete(&GatewayRoute{}, id)
		e.ReloadRoutesCache()
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	// 3. 準備渲染網頁所需的資料結構
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

	// 🔎 檢查網址有沒有帶 ?edit=ID
	var editRoute GatewayRoute
	isEditing := false
	editID := r.URL.Query().Get("edit")
	if editID != "" {
		if err := e.DB.First(&editRoute, editID).Error; err == nil {
			isEditing = true
		}
	}

	// 封裝大包裹丟給前端 HTML
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
		<title>Go-digiRunner 控制台</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
	</head>
	<body class="bg-light">
		<div class="container py-5">
			<div class="d-flex justify-content-between align-items-center mb-4">
				<h1 class="text-primary m-0">⚙️ Go-digiRunner 網關控制台</h1>
				<span class="badge bg-success p-2">動態管理模組完全體</span>
			</div>
			
			<div class="card mb-4 shadow-sm border-{{if .IsEditing}}warning{{else}}dark{{end}}">
				<div class="card-header bg-{{if .IsEditing}}warning text-dark{{else}}dark text-white{{end}} fw-bold">
					{{if .IsEditing}}✏️ 編輯微服務 API 路由表規則{{else}}➕ 註冊新微服務 API{{end}}
					{{if .IsEditing}}<a href="/admin" class="btn btn-sm btn-secondary float-end">取消編輯</a>{{end}}
				</div>
				<div class="card-body">
					<form method="POST" action="/admin" class="row g-3">
						<input type="hidden" name="id" value="{{if .IsEditing}}{{.EditRoute.ID}}{{end}}">
						
						<div class="col-md-4">
							<label class="form-label fw-bold">網關前綴 (Prefix)</label>
							<input type="text" name="prefix" class="form-control" placeholder="如: /api" value="{{if .IsEditing}}{{.EditRoute.Prefix}}{{end}}" required>
						</div>
						<div class="col-md-6">
							<label class="form-label fw-bold">真實後端目標 (多目標以半形逗號區隔)</label>
							<input type="text" name="target" class="form-control" placeholder="如: http://127.0.0.1:8081, http://127.0.0.1:8082" value="{{if .IsEditing}}{{.EditRoute.Target}}{{end}}" required>
						</div>
						<div class="col-md-2 d-flex align-items-end">
							<button type="submit" class="btn btn-{{if .IsEditing}}warning{{else}}success{{end}} w-100 fw-bold">
								{{if .IsEditing}}儲存變更{{else}}即時上線{{end}}
							</button>
						</div>
					</form>
				</div>
			</div>

			<div class="card shadow-sm">
				<div class="card-header bg-secondary text-white fw-bold">📋 執行中 API 路由表 (最長前綴優先級排序)</div>
				<div class="card-body p-0">
					<table class="table table-striped table-hover m-0 align-middle">
						<thead class="table-dark">
							<tr>
								<th style="width: 8%">ID</th>
								<th style="width: 25%">網關入口路徑 (Prefix)</th>
								<th style="width: 40%">後端微服務目標 (Target URL)</th>
								<th style="width: 12%">呼叫次數 (Hits)</th>
								<th style="width: 15%">操作</th>
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
										{{.Hits}} 次呼叫
									</span>
								</td>
								<td>
									<a href="/admin?edit={{.ID}}" class="btn btn-outline-warning btn-sm me-1">編輯</a>
									<a href="/admin/delete/{{.ID}}" class="btn btn-outline-danger btn-sm">下線</a>
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
		e.DB.Create(&GatewayRoute{Prefix: "/service-a", Target: "https://httpbin.org"})
		e.DB.Create(&GatewayRoute{Prefix: "/service-b", Target: "https://api.github.com"})
	}
	e.DB.Model(&ClientKey{}).Count(&count)
	if count == 0 {
		e.DB.Create(&ClientKey{KeyName: "admin-pass-558", Owner: "NCU_CSIE_Admin"})
	}
}

// WithRateLimit 流量限制中間件
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
			log.Printf("⚠️  [流量控制] 惡意刷流量連線遭攔截！拒絕 IP: %s", ip)
			http.Error(w, "🛑 Too Many Requests: 您呼叫得太頻繁了，請稍後再試 (429)", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
