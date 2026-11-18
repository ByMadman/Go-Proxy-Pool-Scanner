package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"
)

// sessionTTL 会话有效期。
const sessionTTL = 7 * 24 * time.Hour

// User 管理员账号。
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

// HashPassword 使用随机盐 + 多次 SHA-256 迭代生成口令哈希（格式：saltHex$hashHex）。
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return hex.EncodeToString(salt) + "$" + derive(salt, pw)
}

// VerifyPassword 校验明文口令与存储哈希是否一致。
func VerifyPassword(pw, stored string) bool {
	parts := split2(stored, '$')
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil || len(salt) == 0 {
		return false
	}
	return derive(salt, pw) == parts[1]
}

func derive(salt []byte, pw string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(pw))
	prev := h.Sum(nil)
	for i := 0; i < 50000; i++ {
		h.Reset()
		h.Write(prev)
		h.Write([]byte(pw))
		prev = h.Sum(nil)
	}
	return hex.EncodeToString(prev)
}

func split2(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// CountUsers 返回账号数量。
func (s *Store) CountUsers() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetUserByName 按用户名查询账号。
func (s *Store) GetUserByName(name string) (User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id,username,password_hash,created_at FROM users WHERE username=?`, name)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt); err == sql.ErrNoRows {
		return u, false, nil
	} else if err != nil {
		return u, false, err
	}
	return u, true, nil
}

// CreateUser 新建账号。
func (s *Store) CreateUser(name, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO users (username,password_hash) VALUES (?,?)`, name, hash)
	return err
}

// SetUserPassword 修改指定账号的口令。
func (s *Store) SetUserPassword(name, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE username=?`, hash, name)
	return err
}

// EnsureDefaultAdmin 当无任何账号时，用给定用户名/口令创建首个管理员。
// 仅在账号表为空时生效，不会覆盖已有账号。
func (s *Store) EnsureDefaultAdmin(username, password string) error {
	n, err := s.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "admin123"
	}
	return s.CreateUser(username, HashPassword(password))
}

// CreateSession 为新登录创建会话，返回令牌与过期时间。
func (s *Store) CreateSession(username string) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(buf)
	expires := time.Now().Add(sessionTTL)
	if _, err := s.db.Exec(`INSERT INTO sessions (token,username,expires_at) VALUES (?,?,?)`, token, username, expires); err != nil {
		return "", time.Time{}, err
	}
	_ = s.cleanSessionsLocked()
	return token, expires, nil
}

// ValidSession 校验令牌是否有效（未过期），返回对应用户名。
func (s *Store) ValidSession(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		username string
		expires  time.Time
	)
	if err := s.db.QueryRow(`SELECT username,expires_at FROM sessions WHERE token=?`, token).Scan(&username, &expires); err != nil {
		return "", false
	}
	if time.Now().After(expires) {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
		return "", false
	}
	return username, true
}

// DeleteSession 删除会话（登出）。
func (s *Store) DeleteSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (s *Store) cleanSessionsLocked() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}

// SessionTokenFromRequest 从请求中取出会话令牌（优先 Authorization 头，其次 Cookie）。
func SessionTokenFromRequest(r *http.Request) string {
	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 7 && ah[:7] == "Bearer " {
			return ah[7:]
		}
	}
	if ck, err := r.Cookie("ps_token"); err == nil && ck.Value != "" {
		return ck.Value
	}
	return ""
}
