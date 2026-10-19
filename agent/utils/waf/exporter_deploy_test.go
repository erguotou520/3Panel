package waf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 周期检查每分钟跑一次，内容未变时必须跳过写盘并报告 changed=false ——
// 既少写 SSD，也让调用方能据此决定要不要 reload OpenResty。
// 漏报 changed 的后果是「Lua 更新了但 worker 还跑旧代码」。
func TestDeployLuaModulesIfChangedSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{"a.lua": []byte("content-1")}

	changed, err := DeployLuaModulesIfChanged(files, dir)
	if err != nil {
		t.Fatalf("首次部署: %v", err)
	}
	if !changed {
		t.Fatal("首次部署必须报告 changed=true")
	}
	dest := filepath.Join(HostWAFDir(dir), "a.lua")

	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(dest, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	changed, err = DeployLuaModulesIfChanged(files, dir)
	if err != nil {
		t.Fatalf("二次部署: %v", err)
	}
	if changed {
		t.Fatal("内容未变却报告 changed=true（会导致每分钟都 reload）")
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fi.ModTime().Equal(past) {
		t.Fatal("内容未变却重写了文件")
	}

	// 内容变了必须写下去并报告 changed —— 否则升级带来的新逻辑推不到数据面
	changed, err = DeployLuaModulesIfChanged(map[string][]byte{"a.lua": []byte("content-2")}, dir)
	if err != nil {
		t.Fatalf("变更部署: %v", err)
	}
	if !changed {
		t.Fatal("内容变化必须报告 changed=true")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "content-2" {
		t.Fatalf("内容变化后应写入新内容，实际 %q", got)
	}
}
