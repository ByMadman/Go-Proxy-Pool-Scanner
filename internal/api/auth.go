package api

import (
	"net/http"
	"strings"
	"time"

	"proxyscanner/internal/store"
)

// publicPaths 无需登录即可访问的接口。
var publicPaths = map[string]bool{
	"GET /api/health":  true,
	"POST /api/login":  true,
}

// isPublic 判断请求是否跳过鉴权。代理池提取接口（export/extract）由 handler 自行判定令牌/密钥。
func isPublic(r *http.Request) bool {
	if publicPaths[r.Method+" "+r.URL.Path] {
		return true
	}
	return r.URL.Path == "/api/proxies/export" || r.URL.Path == "/api/proxies/extract"
}

// authUser 校验请求中的会话令牌是否有效，返回用户名。
func (s *Server) authUser(r *http.Request) (string, bool) {
	return s.store.ValidSession(store.SessionTokenFromRequest(r))
}

// authMiddleware 保护所有 /api 接口（白名单除外）；静态资源（前端页面/JS/CSS）放行。
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if isPublic(r) {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := s.authUser(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		writeErr(w, 401, "未登录或登录已过期")
	})
}

// POST /api/login {username,password}
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, ok, err := s.store.GetUserByName(req.Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok || !store.VerifyPassword(req.Password, u.PasswordHash) {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	token, expires, err := s.store.CreateSession(u.Username)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 种 Cookie：便于 SSE 与导出文件下载自动携带凭据（同站点请求）
	http.SetCookie(w, &http.Cookie{
		Name:     "ps_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	writeOK(w, map[string]any{
		"token":     token,
		"username":  u.Username,
		"expiresAt": expires.Format(time.RFC3339),
	})
}

// POST /api/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := store.SessionTokenFromRequest(r); token != "" {
		_ = s.store.DeleteSession(token)
	}
	http.SetCookie(w, &http.Cookie{Name: "ps_token", Value: "", Path: "/", MaxAge: -1})
	writeOK(w, true)
}

// GET /api/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authUser(r)
	if !ok {
		writeErr(w, 401, "未登录或登录已过期")
		return
	}
	writeOK(w, map[string]any{"username": u})
}

// POST /api/admin/password {oldPassword,newPassword}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authUser(r)
	if !ok {
		writeErr(w, 401, "未登录或登录已过期")
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.NewPassword) < 6 {
		writeErr(w, 400, "新密码至少 6 位")
		return
	}
	user, ok2, err := s.store.GetUserByName(u)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok2 || !store.VerifyPassword(req.OldPassword, user.PasswordHash) {
		writeErr(w, 400, "原密码错误")
		return
	}
	if err := s.store.SetUserPassword(u, store.HashPassword(req.NewPassword)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// extractAllowed 判断代理池提取请求是否放行：有效会话令牌 或 配置的提取密钥。
func (s *Server) extractAllowed(r *http.Request) bool {
	if u, ok := s.authUser(r); ok && u != "" {
		return true
	}
	if s.extractKey == "" {
		return false
	}
	key := r.URL.Query().Get("apikey")
	if key == "" {
		key = r.Header.Get("X-Api-Key")
	}
	return key == s.extractKey
}
