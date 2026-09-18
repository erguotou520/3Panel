package files

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/3panel-dev/3panel/core/constant"
	"github.com/3panel-dev/3panel/core/global"
	"github.com/3panel-dev/3panel/core/utils/cmd"
	"github.com/3panel-dev/3panel/core/utils/req_helper"
)

func CopyFile(src, dst string, withName bool) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	if path.Base(src) != path.Base(dst) && !withName {
		dst = path.Join(dst, path.Base(src))
	}
	if _, err := os.Stat(path.Dir(dst)); err != nil {
		if os.IsNotExist(err) {
			_ = os.MkdirAll(path.Dir(dst), os.ModePerm)
		}
	}
	target, err := os.OpenFile(dst+"_temp", os.O_RDWR|os.O_CREATE|os.O_TRUNC, constant.FilePerm)
	if err != nil {
		return err
	}
	defer target.Close()

	if _, err = io.Copy(target, source); err != nil {
		return err
	}
	if err = os.Rename(dst+"_temp", dst); err != nil {
		return err
	}
	return nil
}

func CopyItem(isDir, withName bool, src, dst string) error {
	if path.Base(src) != path.Base(dst) && !withName {
		dst = path.Join(dst, path.Base(src))
	}
	srcInfo, err := os.Stat(path.Dir(src))
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); err != nil {
		if os.IsNotExist(err) {
			_ = os.MkdirAll(dst, srcInfo.Mode())
		}
	}
	matches, err := filepath.Glob(src)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("no files matched %s", src)
	}
	cmdArgs := append([]string{"-rf"}, matches...)
	cmdText := fmt.Sprintf("cp -rf %s %s", strings.Join(matches, " "), dst+"/")
	if !isDir {
		cmdArgs = append([]string{"-f"}, matches...)
		cmdText = fmt.Sprintf("cp -f %s %s", strings.Join(matches, " "), dst+"/")
	}
	cmdArgs = append(cmdArgs, dst+"/")
	stdout, err := cmd.NewCommandMgr(cmd.WithTimeout(60*time.Second)).RunWithStdout("cp", cmdArgs...)
	if err != nil {
		return fmt.Errorf("handle %s failed, stdout: %s, err: %v", cmdText, stdout, err)
	}
	return nil
}

func CopyFileWithRename(src, dst string) error {
	srcInfo, err := os.Stat(path.Dir(src))
	if err != nil {
		return err
	}
	if _, err := os.Stat(path.Dir(dst)); err != nil {
		if os.IsNotExist(err) {
			_ = os.MkdirAll(path.Dir(dst), srcInfo.Mode())
		}
	}
	cmdMgr := cmd.NewCommandMgr()
	if err := cmdMgr.Run("cp", "-f", src, dst+".tmp"); err != nil {
		return fmt.Errorf("handle cp file failed, err: %v", err)
	}
	if err = cmdMgr.Run("mv", dst+".tmp", dst); err != nil {
		return err
	}
	return nil
}

func HandleTar(sourceDir, targetDir, name, exclusionRules string, secret string) error {
	if _, err := os.Stat(targetDir); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(targetDir, os.ModePerm); err != nil {
			return err
		}
	}

	targetFile := path.Join(targetDir, name)
	excludeText, excludeArgs := buildTarExcludeArgs(exclusionRules)
	tarPathText, tarPathArgs := buildTarPathArgs(sourceDir)
	if len(secret) != 0 {
		logTarEncryptCommand(targetFile, excludeText, tarPathText, secret)
		stdout, err := runTarEncrypt(targetFile, excludeArgs, tarPathArgs, secret)
		if err != nil && len(stdout) != 0 {
			global.LOG.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
			return fmt.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
		}
		return nil
	}

	global.LOG.Debug(fmt.Sprintf("tar -zcf %s %s %s", targetFile, excludeText, tarPathText))
	stdout, err := runTar(targetFile, excludeArgs, tarPathArgs)
	if err != nil && len(stdout) != 0 {
		global.LOG.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
		return fmt.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
	}
	return nil
}

func buildTarExcludeArgs(exclusionRules string) (string, []string) {
	exMap := make(map[string]struct{})
	excludes := strings.Split(exclusionRules, ",")
	excludeRules := ""
	excludeArgs := []string{}
	for _, exclude := range excludes {
		if len(exclude) == 0 {
			continue
		}
		if _, ok := exMap[exclude]; ok {
			continue
		}
		excludeRules += fmt.Sprintf(" --exclude '%s'", exclude)
		excludeArgs = append(excludeArgs, "--exclude", exclude)
		exMap[exclude] = struct{}{}
	}
	return excludeRules, excludeArgs
}

func buildTarPathArgs(sourceDir string) (string, []string) {
	tarPath := ""
	tarPathArgs := []string{}
	if strings.Contains(sourceDir, "/") {
		itemDir := strings.ReplaceAll(sourceDir[strings.LastIndex(sourceDir, "/"):], "/", "")
		aheadDir := sourceDir[:strings.LastIndex(sourceDir, "/")]
		if len(aheadDir) == 0 {
			aheadDir = "/"
		}
		tarPath += fmt.Sprintf("-C %s %s", aheadDir, itemDir)
		tarPathArgs = append(tarPathArgs, "-C", aheadDir, itemDir)
	} else {
		tarPath = sourceDir
		tarPathArgs = append(tarPathArgs, sourceDir)
	}
	return tarPath, tarPathArgs
}

func logTarEncryptCommand(targetFile, excludeRules, tarPath, secret string) {
	extraCmd := "| openssl enc -aes-256-cbc -salt -k '" + secret + "' -out"
	command := fmt.Sprintf("tar -zcf %s %s %s %s", " -"+excludeRules, tarPath, extraCmd, targetFile)
	global.LOG.Debug(strings.ReplaceAll(command, fmt.Sprintf(" '%s' ", secret), " ****** "))
}

func runTar(targetFile string, excludeArgs, tarPathArgs []string) (string, error) {
	tarArgs := append([]string{"-zcf", targetFile}, excludeArgs...)
	tarArgs = append(tarArgs, tarPathArgs...)
	return cmd.NewCommandMgr(cmd.WithTimeout(24*time.Hour), cmd.WithIgnoreExist1()).RunWithStdout("tar", tarArgs...)
}

func HandleUnTar(sourceFile, targetDir string, secret string) error {
	if _, err := os.Stat(targetDir); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(targetDir, os.ModePerm); err != nil {
			return err
		}
	}
	if len(secret) != 0 {
		logTarDecryptCommand(sourceFile, targetDir, secret)
		stdout, err := runTarDecrypt(sourceFile, targetDir, secret)
		if err != nil {
			global.LOG.Errorf("do handle untar failed, stdout: %s, err: %v", stdout, err)
			return errors.New(stdout)
		}
		return nil
	}

	global.LOG.Debug(fmt.Sprintf("tar zxvf '%s' -C '%s'", sourceFile, targetDir))
	stdout, err := runUnTar(sourceFile, targetDir)
	if err != nil {
		global.LOG.Errorf("do handle untar failed, stdout: %s, err: %v", stdout, err)
		return errors.New(stdout)
	}
	return nil
}

func logTarDecryptCommand(sourceFile, targetDir, secret string) {
	extraCmd := "openssl enc -d -aes-256-cbc -k '" + secret + "' -in " + sourceFile + " | "
	command := fmt.Sprintf("%s tar -zxvf - -C %s", extraCmd, targetDir+" > /dev/null 2>&1")
	global.LOG.Debug(strings.ReplaceAll(command, fmt.Sprintf(" '%s' ", secret), " ****** "))
}

func runUnTar(sourceFile, targetDir string) (string, error) {
	return cmd.NewCommandMgr(cmd.WithTimeout(24*time.Hour)).RunWithStdout("tar", "zxf", sourceFile, "-C", targetDir)
}

func runTarEncrypt(targetFile string, excludeArgs, tarPathArgs []string, secret string) (string, error) {
	tarArgs := append([]string{"-zcf", "-"}, excludeArgs...)
	tarArgs = append(tarArgs, tarPathArgs...)
	return cmd.NewCommandMgr(cmd.WithTimeout(24*time.Hour)).RunPipe(
		cmd.PipeCommand{Name: "tar", Args: tarArgs},
		cmd.PipeCommand{Name: "openssl", Args: []string{"enc", "-aes-256-cbc", "-salt", "-pass", "env:BACKUP_SECRET", "-out", targetFile}, Env: []string{"BACKUP_SECRET=" + secret}},
	)
}

func runTarDecrypt(sourceFile, targetDir, secret string) (string, error) {
	return cmd.NewCommandMgr(cmd.WithTimeout(24*time.Hour)).RunPipe(
		cmd.PipeCommand{Name: "openssl", Args: []string{"enc", "-d", "-aes-256-cbc", "-pass", "env:BACKUP_SECRET", "-in", sourceFile}, Env: []string{"BACKUP_SECRET=" + secret}},
		cmd.PipeCommand{Name: "tar", Args: []string{"-zxf", "-", "-C", targetDir}},
	)
}

func DownloadFile(url, dst string) error {
	resp, err := req_helper.HandleGet(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create download file [%s] error, err %s", dst, err.Error())
	}
	defer out.Close()

	if _, err = io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("save download file [%s] error, err %s", dst, err.Error())
	}
	return nil
}

func DownloadFileWithProxyStream(url, dst string) error {
	resp, err := req_helper.HandleGetWithProxy(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("download file [%s] failed, status code: %d", url, resp.StatusCode)
	}

	tmpDst := dst + ".part"
	_ = os.Remove(tmpDst)
	out, err := os.Create(tmpDst)
	if err != nil {
		return fmt.Errorf("create download file [%s] error, err %s", dst, err.Error())
	}
	success := false
	defer func() {
		_ = out.Close()
		if !success {
			_ = os.Remove(tmpDst)
		}
	}()

	n, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("save download file [%s] error, err %s", dst, err.Error())
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		return fmt.Errorf("save download file [%s] error, content-length mismatch: expected %d, actual %d", dst, resp.ContentLength, n)
	}
	if err = out.Sync(); err != nil {
		return fmt.Errorf("sync download file [%s] error, err %s", dst, err.Error())
	}
	if err = os.Rename(tmpDst, dst); err != nil {
		return fmt.Errorf("rename download file [%s] error, err %s", dst, err.Error())
	}
	success = true
	return nil
}

// FileSHA256 returns the lowercase hex sha256 digest of the file at filePath.
func FileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFileSHA256 compares the file at filePath against an expected sha256
// digest (lowercase or uppercase hex, 64 chars).
func VerifyFileSHA256(filePath, expected string) error {
	sum, err := FileSHA256(filePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, strings.TrimSpace(expected)) {
		return fmt.Errorf("sha256 mismatch for %s: expected %s, got %s", filePath, expected, sum)
	}
	return nil
}

// ParseSHA256File extracts a sha256 digest from the content of a
// sha256sum-style checksum file. Both "<hex>" and "<hex>  <filename>" lines are
// accepted; comment lines and blank lines are skipped. It returns an empty
// string when no valid digest is present.
func ParseSHA256File(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidate := strings.ToLower(fields[0])
		if len(candidate) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(candidate); err != nil {
			continue
		}
		return candidate
	}
	return ""
}

func Stat(path string) bool {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func GetFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := md5.New()

	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
