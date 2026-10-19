package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	wafutils "github.com/3panel-dev/3panel/agent/utils/waf"
)

// 升级 agent 二进制后，已启用 WAF 的站点不会再走 SetWebsiteWAF(enable=true)，
// 若不主动刷新，数据面会继续跑旧 Lua，而 rules.json 已是新格式 ——
// 新字段被老代码忽略、新规则类型被跳过，表现为「升了级但新功能不生效」。
func TestRefreshLuaModulesOverwritesStaleFiles(t *testing.T) {
	root := t.TempDir()
	wafDir := wafutils.HostWAFDir(root)
	if err := os.MkdirAll(wafDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stale := filepath.Join(wafDir, "access.lua")
	if err := os.WriteFile(stale, []byte("-- 旧版本占位"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	refreshLuaModules(root)

	got, err := os.ReadFile(stale)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) == "-- 旧版本占位" || len(got) < 1024 {
		t.Fatalf("access.lua 未被内置版本覆盖，长度 %d", len(got))
	}

	// 这次上线新增的区间判定必须真的写进去了：否则 geo 规则仍走逐条解析。
	iputils, err := os.ReadFile(filepath.Join(wafDir, "iputils.lua"))
	if err != nil {
		t.Fatalf("read iputils: %v", err)
	}
	if !strings.Contains(string(iputils), "prepare_cidrs") {
		t.Fatal("iputils.lua 里没有 prepare_cidrs，说明写入的不是当前版本")
	}
}

// 从未开启过 WAF 的机器上不该凭空创建 www/waf 目录。
func TestRefreshLuaModulesSkipsWhenDirMissing(t *testing.T) {
	root := t.TempDir()
	refreshLuaModules(root)
	if _, err := os.Stat(wafutils.HostWAFDir(root)); !os.IsNotExist(err) {
		t.Fatalf("waf 目录不该被创建，stat err = %v", err)
	}
}
