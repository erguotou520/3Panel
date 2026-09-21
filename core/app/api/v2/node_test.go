package v2

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestOriginUsesRequestTransport(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "http", url: "http://192.168.1.10:9543/api/v2/core/nodes", want: "http://192.168.1.10:9543"},
		{name: "https", url: "https://panel.example.com/api/v2/core/nodes", want: "https://panel.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest("POST", tt.url, nil)
			ctx.Request.RemoteAddr = ""
			if got := requestOrigin(ctx); got != tt.want {
				t.Fatalf("requestOrigin() = %q, want %q", got, tt.want)
			}
		})
	}
}
