package dir

import (
	"path"

	"github.com/3panel-dev/3panel/agent/global"
	"github.com/3panel-dev/3panel/agent/utils/files"
)

func Init() {
	fileOp := files.NewFileOp()
	baseDir := global.CONF.Base.InstallDir
	_, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/docker/compose/"))

	global.Dir.BaseDir, _ = fileOp.CreateDirWithPath(true, baseDir)
	global.Dir.DataDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel"))
	global.Dir.DbDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/db"))
	global.Dir.LogDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/log"))
	global.Dir.TaskDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/log/task"))
	global.Dir.TmpDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/tmp"))

	global.Dir.AppDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/apps"))
	global.Dir.ResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource"))
	global.Dir.IconCacheDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/icon"))
	global.Dir.AppResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/apps"))
	global.Dir.AppInstallDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/apps"))
	global.Dir.LocalAppResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/apps/local"))
	global.Dir.LocalAppInstallDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/apps/local"))
	global.Dir.RemoteAppResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/apps/remote"))
	global.Dir.CustomAppResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/apps/custom"))
	global.Dir.OfflineAppResourceDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/resource/offline"))
	global.Dir.RuntimeDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/runtime"))
	global.Dir.RecycleBinDir, _ = fileOp.CreateDirWithPath(true, "/.3panel_clash")
	global.Dir.SSLLogDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/log/ssl"))
	global.Dir.McpDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/mcp"))
	global.Dir.ConvertLogDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/log/convert"))
	global.Dir.TensorRTLLMDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/ai/tensorrt_llm"))
	global.Dir.FirewallDir, _ = fileOp.CreateDirWithPath(true, path.Join(baseDir, "3panel/firewall"))
}
