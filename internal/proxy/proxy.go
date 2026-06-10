package proxy

import (
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"

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

// Engine 網關核心引擎，封裝了所有資料庫與記憶體狀態
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

// NewEngine 初始化網關引擎
func NewEngine(db *gorm.DB) *Engine {
	e := &Engine{
		DB:           db,
		routeCache:   make(map[string][]string),
		routeIndexes: make(map[string]int),
		metrics:      make(map[string]int),
		ipLimiters:   make(map[string]*rate.Limiter),
	}
	// 自動遷移
	e.DB.AutoMigrate(&GatewayRoute{}, &ClientKey{})
	e.initSeedData()
	e.ReloadRoutesCache()
	return e
}

// ReloadRoutesCache 熱加載快取（最長前綴匹配排序）
// ReloadRoutesCache 熱加載快取（最長前綴匹配排序 + 負載平衡解析）
func (e *Engine) ReloadRoutesCache() {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	var routes []GatewayRoute
	e.DB.Find(&routes)

	e.routeCache = make(map[string][]string)
	e.routeIndexes = make(map[string]int) // 🔥 每次重新載入時重設輪詢索引
	e.sortedKeys = []string{}

	for _, r := range routes {
		// 🚀 關鍵核心：用逗號切開多個後端網址
		rawTargets := strings.Split(r.Target, ",")
		var cleanTargets []string
		for _, t := range rawTargets {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				cleanTargets = append(cleanTargets, trimmed)
			}
		}

		e.routeCache[r.Prefix] = cleanTargets
		e.routeIndexes[r.Prefix] = 0 // 從第 0 台機器開始輪詢
		e.sortedKeys = append(e.sortedKeys, r.Prefix)
	}

	sort.Slice(e.sortedKeys, func(i, j int) bool {
		return len(e.sortedKeys[i]) > len(e.sortedKeys[j])
	})

	log.Printf("🔄 [Engine] 路由與負載平衡快取已熱加載。優先級: %v", e.sortedKeys)
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

		var apiKey string
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		}

		if apiKey == "" {
			apiKey = r.Header.Get("X-DigiRunner-Key")
		}

		if apiKey == "" {
			http.Error(w, "🔒 Unauthorized: 缺少相容之認證憑證", http.StatusUnauthorized)
			return
		}

		var clientKey ClientKey
		if err := e.DB.Where("key_name = ?", apiKey).First(&clientKey).Error; err != nil {
			http.Error(w, "🔒 Forbidden: 憑證無效", http.StatusForbidden)
			return
		}
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
	var targets []string // 🚀 拿出來的是該路由所有的後端機器清單
	var routePrefix string

	for _, prefix := range e.sortedKeys {
		if strings.HasPrefix(currentPath, prefix) {
			routePrefix = prefix
			targets = e.routeCache[prefix]
			break
		}
	}
	e.cacheMutex.RUnlock()

	// 防呆：如果找不到或陣列是空的
	if len(targets) == 0 {
		http.Error(w, "🚫 Go-digiRunner: 未註冊該 API 路由", http.StatusNotFound)
		return
	}

	// 🚀 【負載平衡演算法核心】
	e.indexMutex.Lock()
	currentIndex := e.routeIndexes[routePrefix]
	targetURLStr := targets[currentIndex] // 🎯 決定這筆請求要送給哪一台機器！

	// 往下輪一個位置，如果到底了就透過取餘數 (%) 自動歸零
	e.routeIndexes[routePrefix] = (currentIndex + 1) % len(targets)
	e.indexMutex.Unlock()

	// 📊 數據統計
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

// AdminHandler 後台 GUI 邏輯
func (e *Engine) AdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		prefix := r.FormValue("prefix")
		target := r.FormValue("target")
		if prefix != "" && target != "" {
			if !strings.HasPrefix(prefix, "/") {
				prefix = "/" + prefix
			}
			e.DB.Create(&GatewayRoute{Prefix: prefix, Target: target})
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

	var routes []GatewayRoute
	e.DB.Find(&routes)

	type DisplayRoute struct {
		ID     uint
		Prefix string
		Target string
		Hits   int
	}

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
				<span class="badge bg-success p-2">模組化架構完全體</span>
			</div>
			
			<div class="card mb-4 shadow-sm">
				<div class="card-header bg-dark text-white fw-bold">➕ 註冊新微服務 API</div>
				<div class="card-body">
					<form method="POST" action="/admin" class="row g-3">
						<div class="col-md-4">
							<input type="text" name="prefix" class="form-control" placeholder="轉發前綴 (如: /api)" required>
						</div>
						<div class="col-md-6">
							<input type="url" name="target" class="form-control" placeholder="真實後端服務位址 (如: http://127.0.0.1:8080)" required>
						</div>
						<div class="col-md-2">
							<button type="submit" class="btn btn-success w-100 fw-bold">即時上線</button>
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
								<th style="width: 30%">網關入口路徑 (Prefix)</th>
								<th style="width: 40%">後端微服務目標 (Target URL)</th>
								<th style="width: 12%">呼叫次數 (Hits)</th>
								<th style="width: 10%">操作</th>
							</tr>
						</thead>
						<tbody>
							{{range .}}
							<tr>
								<td>{{.ID}}</td>
								<td><code>{{.Prefix}}</code></td>
								<td><a href="{{.Target}}" target="_blank" class="text-decoration-none">{{.Target}}</a></td>
								<td>
									<span class="badge bg-{{if gt .Hits 0}}primary{{else}}secondary{{end}} fs-6">
										{{.Hits}} 次呼叫
									</span>
								</td>
								<td><a href="/admin/delete/{{.ID}}" class="btn btn-outline-danger btn-sm">下線</a></td>
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
	t.Execute(w, displayList)
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

// WithRateLimit 流量限制中間件 (防止用戶惡意刷 API)
func (e *Engine) WithRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 放行管理後台
		if strings.HasPrefix(r.URL.Path, "/admin") {
			next(w, r)
			return
		}

		// 1. 取得客戶端的真實 IP 地址 (切除 Port 部分)
		ip := strings.Split(r.RemoteAddr, ":")[0]

		e.limiterMutex.Lock()
		limiter, exists := e.ipLimiters[ip]
		if !exists {
			// 💡 建立新限制器：
			// rate.Limit(2) 代表每秒「穩定生成 2 個權杖」（每秒只能戳 2 下）
			// 3 代表「水桶總容量」，允許瞬間爆發連點 3 下（Burst）
			limiter = rate.NewLimiter(2, 3)
			e.ipLimiters[ip] = limiter
		}
		e.limiterMutex.Unlock()

		// 2. 檢查水桶裡還有沒有權杖可拿
		if !limiter.Allow() {
			log.Printf("⚠️  [流量控制] 惡意刷流量連線遭攔截！拒絕 IP: %s", ip)
			// 傳回標準的 429 狀態碼
			http.Error(w, "🛑 Too Many Requests: 您呼叫得太頻繁了，請稍後再試 (429)", http.StatusTooManyRequests)
			return
		}

		// 3. 還有權杖，順利通關，交給下一層
		next(w, r)
	}
}
