# garminpersonal

Client Go cho **Garmin Connect Personal API**: đổi API key cá nhân lấy access token (24 giờ),
tìm buổi tập, đọc chi tiết, tải file FIT gốc (ZIP). Chỉ dùng thư viện chuẩn, không phụ thuộc gì khác.

Đường dẫn lấy từ client chính thức của Garmin
([garmin/connect-personal-api-python](https://github.com/garmin/connect-personal-api-python)).
Tên trường JSON của buổi tập chưa được tài liệu hoá, nên các hàm trả `[]byte` JSON thô — người dùng
tự đọc (xem `Taper/be/internal/providers/garminpersonal` làm ví dụ đọc khoan dung).

```go
c := garminpersonal.New("") // rỗng = Garmin thật
raw, err := c.SearchActivities(ctx, apiKey, 0, 50, from, to)
zipBytes, err := c.DownloadActivity(ctx, apiKey, "123456789")
```

- Token đổi từ key được giữ **trong bộ nhớ** theo dấu vân tay của key, không bao giờ ghi ra đĩa.
- Key sai/hết hạn/bị thu hồi → `ErrKeyRejected` (khác lỗi tạm `*HTTPError`).
- Lỗi không bao giờ mang theo key hay thân phản hồi.
- `NewWithHTTP` cho phép gắn `http.Client` riêng (log, proxy).
