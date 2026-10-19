package v2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/3panel-dev/3panel/agent/app/model"
	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/i18n"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// 回归：GET /waf/ip-groups?websiteId=N 曾经用 gin 的 path 参数读取器
// （helper.GetIntParamByKey），而该路由没有 :websiteId 段，于是恒定返回
// "error websiteId in path"，前端 IP 组列表永远是空的。
//
// 这里用真实路由 + query 断言：能解析出 websiteId、按站点过滤、缺失时给参数错误。
func TestListWAFIPGroupsReadsWebsiteIDFromQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.WAFIPGroup{}, &model.Setting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	global.DB = db
	// helper.BadRequest 会走 i18n 取文案，未初始化时 bundle 为 nil 会 panic。
	global.LOG = logrus.New()
	i18n.Init()

	if err := db.Create(&model.WAFIPGroup{
		Name:      "office",
		Scope:     model.WAFScopeSite,
		WebsiteID: 7,
		Enabled:   true,
		CIDRs:     "10.0.0.0/8",
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 另一个站点的组不该出现在结果里 —— 顺带验证按 websiteId 过滤。
	if err := db.Create(&model.WAFIPGroup{
		Name:      "other",
		Scope:     model.WAFScopeSite,
		WebsiteID: 8,
		Enabled:   true,
		CIDRs:     "192.168.0.0/16",
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := gin.New()
	api := &BaseApi{}
	router.GET("/waf/ip-groups", api.ListWAFIPGroups)

	// helper 把业务码放在 body 里，HTTP 恒为 200，所以断言看 body.code。
	type response struct {
		Code int                `json:"code"`
		Data []model.WAFIPGroup `json:"data"`
	}
	call := func(url string) response {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		var r response
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatalf("decode %s: %v, body = %s", url, err, w.Body.String())
		}
		return r
	}

	// 1. 带 query：成功，且只返回本站点的组
	got := call("/waf/ip-groups?websiteId=7")
	if got.Code != http.StatusOK {
		t.Fatalf("query websiteId should succeed, got %s", mustJSON(got))
	}
	if len(got.Data) != 1 || got.Data[0].Name != "office" {
		t.Fatalf("want only the website-7 group, got %s", mustJSON(got))
	}

	// 2. 缺 query：参数错误，而不是 panic 或「site 0 的组」
	if got := call("/waf/ip-groups"); got.Code != http.StatusBadRequest {
		t.Fatalf("missing websiteId should be 400, got %s", mustJSON(got))
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
