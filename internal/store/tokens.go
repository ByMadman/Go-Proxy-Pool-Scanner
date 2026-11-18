package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// ExtractToken 代理池提取令牌。
// count     : 单次提取返回的代理数量上限（<=0 表示不限）
// maxTotal  : 累计可提取的代理总数上限（0 表示不限）
// used      : 累计已提取数量
type ExtractToken struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	Creator   string    `json:"creator"`
	ExpiresAt time.Time `json:"expiresAt"`
	Count     int       `json:"count"`
	MaxTotal  int       `json:"maxTotal"`
	Used      int       `json:"used"`
	Enabled   int       `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

// remaining 返回该令牌剩余的累计可提取额度（maxTotal<=0 表示不限）。
func (t ExtractToken) Remaining() int {
	if t.MaxTotal <= 0 {
		return -1
	}
	r := t.MaxTotal - t.Used
	if r < 0 {
		r = 0
	}
	return r
}

// IsValid 令牌是否有效（启用、未过期、且有剩余额度）。
func (t ExtractToken) IsValid() bool {
	if t.Enabled != 1 {
		return false
	}
	if time.Now().After(t.ExpiresAt) {
		return false
	}
	if t.MaxTotal > 0 && t.Used >= t.MaxTotal {
		return false
	}
	return true
}

// GenerateTokenValue 生成随机令牌值。
func GenerateTokenValue() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "px_" + hex.EncodeToString(b)
}

// CreateToken 新建提取令牌，返回生成的令牌值。
// count<=0 表示单次提取不限数量。
func (s *Store) CreateToken(name, creator string, expiresAt time.Time, count, maxTotal int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count < 0 {
		count = 0
	}
	val := GenerateTokenValue()
	_, err := s.db.Exec(`INSERT INTO tokens (name,token,creator,expires_at,count,max_total) VALUES (?,?,?,?,?,?)`,
		name, val, creator, expiresAt, count, maxTotal)
	if err != nil {
		return "", err
	}
	return val, nil
}

// ListTokens 列出全部提取令牌。
func (s *Store) ListTokens() ([]ExtractToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,name,token,creator,expires_at,count,max_total,used,enabled,created_at FROM tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExtractToken
	for rows.Next() {
		var t ExtractToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Token, &t.Creator, &t.ExpiresAt, &t.Count, &t.MaxTotal, &t.Used, &t.Enabled, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// GetTokenByValue 按令牌值查询。
func (s *Store) GetTokenByValue(val string) (ExtractToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id,name,token,creator,expires_at,count,max_total,used,enabled,created_at FROM tokens WHERE token=?`, val)
	var t ExtractToken
	if err := row.Scan(&t.ID, &t.Name, &t.Token, &t.Creator, &t.ExpiresAt, &t.Count, &t.MaxTotal, &t.Used, &t.Enabled, &t.CreatedAt); err == sql.ErrNoRows {
		return t, false, nil
	} else if err != nil {
		return t, false, err
	}
	return t, true, nil
}

// DeleteToken 删除令牌。
func (s *Store) DeleteToken(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM tokens WHERE id=?`, id)
	return err
}

// SetTokenEnabled 启停令牌。
func (s *Store) SetTokenEnabled(id int64, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE tokens SET enabled=? WHERE id=?`, v, id)
	return err
}

// AddTokenUsed 累加令牌的已提取数量。
func (s *Store) AddTokenUsed(id int64, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tokens SET used = used + ? WHERE id=?`, n, id)
	return err
}
