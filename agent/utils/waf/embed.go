// Package waf 提供 WAF 数据面产物管理：Lua 模块部署、名单导出、日志路径
package waf

import (
	"embed"
	"path"
)

//go:embed lua/*.lua
var luaFS embed.FS

// LuaFiles 返回全部内置 Lua 模块（文件名 -> 内容）
func LuaFiles() (map[string][]byte, error) {
	entries, err := luaFS.ReadDir("lua")
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		content, err := luaFS.ReadFile(path.Join("lua", e.Name()))
		if err != nil {
			return nil, err
		}
		files[e.Name()] = content
	}
	return files, nil
}
