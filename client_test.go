package garminpersonal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExchangeSendsApiKeyAndReadsTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "ApiKey my-key" {
			t.Errorf("sai cách gọi: %s %q", r.Method, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"access_token":"tok-123","expires_in":3600}`))
	}))
	defer server.Close()

	token, err := New(server.URL).Exchange(context.Background(), "  my-key  ")
	if err != nil || token.Value != "tok-123" || !token.Valid() {
		t.Fatalf("%+v %v", token, err)
	}
	if left := time.Until(token.ExpiresAt); left > time.Hour || left < 59*time.Minute {
		t.Fatalf("hạn dùng %v, muốn ~1 giờ", left)
	}
}

func TestParseTokenIsTolerantAboutTheShape(t *testing.T) {
	now := time.Now()
	for name, body := range map[string]string{
		"camelCase": `{"accessToken":"a1"}`, "token": `{"token":"a1"}`, "chuỗi trần": "a1\n",
	} {
		token, err := parseToken([]byte(body), now)
		if err != nil || token.Value != "a1" {
			t.Errorf("%s: %+v %v", name, token, err)
		}
		if !token.ExpiresAt.Equal(now.Add(defaultLifetime)) {
			t.Errorf("%s: không có hạn thì mặc định 24 giờ", name)
		}
	}
	for _, bad := range []string{`{}`, `{"access_token":""}`, `<html>lỗi</html>`, ``} {
		if _, err := parseToken([]byte(bad), now); err == nil {
			t.Errorf("%q phải lỗi", bad)
		}
	}
}

func TestRejectedKeyIsADistinctErrorAndNeverEchoesTheKey(t *testing.T) {
	for _, status := range []int{401, 403} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"detail":"key secret-key-value invalid"}`))
		}))
		_, err := New(server.URL).Exchange(context.Background(), "secret-key-value")
		server.Close()
		if !errors.Is(err, ErrKeyRejected) || strings.Contains(err.Error(), "secret-key-value") {
			t.Fatalf("%d: %v", status, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	if _, err := New(server.URL).Exchange(context.Background(), "k"); err == nil || errors.Is(err, ErrKeyRejected) {
		t.Fatalf("503 là lỗi tạm, không phải key bị từ chối: %v", err)
	}
	if _, err := New("").Exchange(context.Background(), "  "); err == nil {
		t.Fatal("thiếu key phải lỗi")
	}
}

func TestGetRefusesAnyHostThatIsNotGarmin(t *testing.T) {
	client := New("")
	for _, bad := range []string{"http://apis.garmin.com/x", "https://evil.example.com/x", "https://garmin.com.evil.test/x", "ftp://a.garmin.com/x", "not a url"} {
		if _, err := client.Get(context.Background(), Token{Value: "t"}, bad); err == nil {
			t.Errorf("%q không được gọi (token không được rời khỏi Garmin)", bad)
		}
	}
	for host, want := range map[string]bool{"garmin.com": true, "apis.garmin.com": true, "personal.connectapi.garmin.com": true, "garmin.com.evil.test": false, "evilgarmin.com": false} {
		if allowedHost(host) != want {
			t.Errorf("%s: %v", host, !want)
		}
	}
}
