// Package garminpersonal nói chuyện với Garmin Connect Personal API: người dùng tự tạo một
// API key trong Garmin Connect (trang Personal API Key), đổi key lấy access token sống 24 giờ,
// rồi đọc dữ liệu của chính mình (buổi tập JSON/FIT, sức khoẻ). Không có refresh token — hết
// hạn thì đổi lại bằng key; key hết hạn (30 ngày – 1 năm) thì người dùng phải tạo key mới.
//
// Mọi đường dẫn và cách xác thực ở đây lấy từ mã nguồn CHÍNH THỨC của Garmin
// (github.com/garmin/connect-personal-api-python, src/garmin_personal_api): đổi token trả về
// thẳng một JWT dạng text, hạn nằm trong claim `exp`; dữ liệu đọc bằng `Authorization: Bearer`.
// Tên trường của JSON buổi tập thì CHƯA có tài liệu trong repo đó — adapter đọc khoan dung và
// xem JSON thô để biết trường thật; FIT gốc (tải về dạng ZIP) mới là nguồn chính của
// chuỗi mẫu.
package garminpersonal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BaseURL là gốc của Personal API; TokenPath là đường đổi API key lấy access token
// (POST, header Authorization: ApiKey <key>).
const (
	BaseURL   = "https://personal.connectapi.garmin.com"
	TokenPath = "/personalapitoken-service/personal-api/personal-api-key/token"
	// TokenURL giữ lại cho chỗ đã dùng.
	TokenURL = BaseURL + TokenPath
)

// Đường dẫn dữ liệu buổi tập.
const (
	searchPath   = "/activitylist-service/activities/search/activities"
	activityPath = "/activity-service/activity/"
	downloadPath = "/download-service/files/activity/"
)

// defaultLifetime là hạn dùng khi phản hồi không nói: tài liệu ghi token sống 24 giờ.
const defaultLifetime = 24 * time.Hour

// ErrKeyRejected: Garmin từ chối key (sai, đã thu hồi hoặc hết hạn). Người dùng phải tạo key mới.
var ErrKeyRejected = errors.New("garmin từ chối API key (sai, đã thu hồi hoặc hết hạn)")

// Token là access token đã đổi được.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// Valid cho biết token còn dùng được (chừa một phút an toàn).
func (t Token) Valid() bool { return t.Value != "" && time.Until(t.ExpiresAt) > time.Minute }

// Client gọi Garmin Personal API. Dùng chung cho cả tiến trình: key đi theo từng lời gọi chứ
// không nằm trong client, và token đã đổi được giữ trong bộ nhớ theo dấu vân tay của key
// (không bao giờ ghi ra đĩa) để mỗi lượt quét không phải đổi lại.
type Client struct {
	http    *http.Client
	baseURL string

	mu     sync.Mutex
	tokens map[string]Token
}

// New dựng client. baseURL rỗng là Garmin thật; khai khác khi test. Với test cũ truyền
// vào địa chỉ đổi token đầy đủ, vẫn được: phần đuôi TokenPath được cắt bỏ.
func New(baseURL string) *Client {
	baseURL = strings.TrimSuffix(strings.TrimRight(baseURL, "/"), TokenPath)
	if baseURL == "" {
		baseURL = BaseURL
	}

	return NewWithHTTP(baseURL, &http.Client{Timeout: 60 * time.Second})
}

// NewWithHTTP như New nhưng dùng http.Client do người gọi đưa vào (để gắn log, proxy, timeout riêng).
func NewWithHTTP(baseURL string, httpClient *http.Client) *Client {
	baseURL = strings.TrimSuffix(strings.TrimRight(baseURL, "/"), TokenPath)
	if baseURL == "" {
		baseURL = BaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}

	return &Client{http: httpClient, baseURL: baseURL, tokens: map[string]Token{}}
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))

	return hex.EncodeToString(sum[:8])
}

// TokenFor trả access token còn hạn cho một key, đổi mới khi chưa có hoặc sắp hết hạn.
func (c *Client) TokenFor(ctx context.Context, key string) (Token, error) {
	id := fingerprint(key)
	c.mu.Lock()
	cached := c.tokens[id]
	c.mu.Unlock()
	if cached.Valid() {
		return cached, nil
	}

	token, err := c.Exchange(ctx, key)
	if err != nil {
		return Token{}, err
	}
	c.mu.Lock()
	c.tokens[id] = token
	c.mu.Unlock()

	return token, nil
}

// forget bỏ token đã giữ — gọi khi Garmin trả 401 trước hạn (bị thu hồi).
func (c *Client) forget(key string) {
	c.mu.Lock()
	delete(c.tokens, fingerprint(key))
	c.mu.Unlock()
}

// Exchange đổi API key lấy access token.
//
// Dạng phản hồi chưa được tài liệu xác nhận với chúng tôi nên đọc khoan dung: JSON có
// access_token / accessToken / token (kèm expires_in giây hoặc expires_at), hoặc cả thân là
// chính token. Lỗi KHÔNG bao giờ mang theo key hay thân phản hồi.
func (c *Client) Exchange(ctx context.Context, apiKey string) (Token, error) {
	if strings.TrimSpace(apiKey) == "" {
		return Token{}, errors.New("thiếu API key")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+TokenPath, nil)
	if err != nil {
		return Token{}, err
	}
	request.Header.Set("Authorization", "ApiKey "+strings.TrimSpace(apiKey))

	response, err := c.http.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("đổi token Garmin: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))

	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return Token{}, ErrKeyRejected
	case response.StatusCode != http.StatusOK:
		return Token{}, fmt.Errorf("đổi token Garmin: HTTP %d", response.StatusCode)
	}

	return parseToken(body, time.Now())
}

// jwtExpiry đọc claim `exp` của một JWT (không kiểm chữ ký — chỉ để biết khi nào hết hạn).
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}

	return time.Unix(int64(claims.Exp), 0), true
}

func parseToken(body []byte, now time.Time) (Token, error) {
	text := strings.TrimSpace(string(body))
	// Dạng thật (theo client chính thức của Garmin): cả thân phản hồi là một JWT.
	if expires, ok := jwtExpiry(text); ok {
		return Token{Value: text, ExpiresAt: expires}, nil
	}
	var fields map[string]any
	if json.Unmarshal(body, &fields) == nil {
		var value string
		for _, key := range []string{"access_token", "accessToken", "token", "jwt"} {
			if s, ok := fields[key].(string); ok && s != "" {
				value = s

				break
			}
		}
		if value == "" {
			return Token{}, errors.New("đổi token Garmin: phản hồi không có access_token")
		}
		expires := now.Add(defaultLifetime)
		for _, key := range []string{"expires_in", "expiresIn"} {
			if seconds, ok := fields[key].(float64); ok && seconds > 0 {
				expires = now.Add(time.Duration(seconds) * time.Second)
			}
		}
		if stamp, ok := fields["expires_at"].(float64); ok && stamp > 0 {
			expires = time.Unix(int64(stamp), 0)
		}

		return Token{Value: value, ExpiresAt: expires}, nil
	}
	if text != "" && !strings.ContainsAny(text, " \n\t<{") {
		return Token{Value: text, ExpiresAt: now.Add(defaultLifetime)}, nil
	}

	return Token{}, errors.New("đổi token Garmin: không đọc được phản hồi")
}

// Response là kết quả một lời gọi GET có xác thực.
type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

// Get gọi một địa chỉ của Garmin bằng access token. Chỉ gửi tới host *.garmin.com: token
// là thứ có thể đọc cả kho dữ liệu sức khoẻ, không được rơi sang chỗ khác dù do gõ nhầm.
func (c *Client) Get(ctx context.Context, token Token, rawURL string) (Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || !allowedHost(parsed.Hostname()) {
		return Response{}, fmt.Errorf("chỉ gọi https tới *.garmin.com, không gọi %q", rawURL)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Response{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token.Value)
	request.Header.Set("Accept", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return Response{}, fmt.Errorf("gọi Garmin: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<20))

	return Response{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body}, nil
}

func allowedHost(host string) bool {
	host = strings.ToLower(host)

	return host == "garmin.com" || strings.HasSuffix(host, ".garmin.com")
}

// HTTPError là phản hồi không thành công của Garmin cho một lời gọi dữ liệu.
type HTTPError struct {
	Status int
	Path   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("garmin %s: HTTP %d", e.Path, e.Status) }

// do gọi một đường dẫn dữ liệu bằng key (đổi/dùng lại token trong bộ nhớ). Gặp 401 thì bỏ token
// đã giữ, đổi lại một lần rồi gọi lại: token có thể bị thu hồi trước hạn (client chính thức của
// Garmin cũng nói vậy). Không thử lại lần thứ hai, và không bao giờ đưa key hay thân phản hồi vào lỗi.
func (c *Client) do(ctx context.Context, key, path string, params url.Values, accept string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		token, err := c.TokenFor(ctx, key)
		if err != nil {
			return nil, err
		}
		target := c.baseURL + path
		if len(params) > 0 {
			target += "?" + params.Encode()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token.Value)
		request.Header.Set("Accept", accept)

		response, err := c.http.Do(request)
		if err != nil {
			return nil, fmt.Errorf("gọi Garmin %s: %w", path, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<20))
		response.Body.Close()
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.forget(key)

			continue
		}
		if response.StatusCode != http.StatusOK {
			return nil, &HTTPError{Status: response.StatusCode, Path: path}
		}
		if readErr != nil {
			return nil, fmt.Errorf("đọc phản hồi Garmin %s: %w", path, readErr)
		}

		return body, nil
	}
}

// SearchActivities liệt kê buổi tập (phân trang theo số đếm: start, limit) trong khoảng ngày
// [from, to]. Trả thân JSON nguyên văn — phần dựng Summary nằm ở adapter.
func (c *Client) SearchActivities(ctx context.Context, key string, start, limit int, from, to time.Time) ([]byte, error) {
	params := url.Values{"start": {fmt.Sprint(start)}, "limit": {fmt.Sprint(limit)}}
	if !from.IsZero() {
		params.Set("startDate", from.Format("2006-01-02"))
	}
	if !to.IsZero() {
		params.Set("endDate", to.Format("2006-01-02"))
	}

	return c.do(ctx, key, searchPath, params, "application/json")
}

// Activity trả JSON tóm tắt/chi tiết của một buổi.
func (c *Client) Activity(ctx context.Context, key, activityID string) ([]byte, error) {
	if !ValidActivityID(activityID) {
		return nil, fmt.Errorf("id buổi tập Garmin không hợp lệ")
	}

	return c.do(ctx, key, activityPath+activityID, nil, "application/json")
}

// DownloadActivity tải file gốc của buổi tập: một ZIP chứa file .fit.
func (c *Client) DownloadActivity(ctx context.Context, key, activityID string) ([]byte, error) {
	if !ValidActivityID(activityID) {
		return nil, fmt.Errorf("id buổi tập Garmin không hợp lệ")
	}
	body, err := c.do(ctx, key, downloadPath+activityID, nil, "application/zip, application/x-zip-compressed, application/octet-stream")
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("Garmin trả file gốc rỗng")
	}

	return body, nil
}

// ValidActivityID chỉ nhận số nguyên dương: id đi thẳng vào đường dẫn, không được chứa "../".
func ValidActivityID(id string) bool {
	if id == "" || len(id) > 20 {
		return false
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}

	return id != "0" && !strings.HasPrefix(id, "0")
}

// Settings đọc hồ sơ cài đặt của chủ key — một lời gọi đọc nhẹ để biết key dùng được thật
// (đổi được token chưa chắc đã đọc được dữ liệu).
func (c *Client) Settings(ctx context.Context, key string) ([]byte, error) {
	return c.do(ctx, key, "/userprofile-service/userprofile/settings", nil, "application/json")
}
