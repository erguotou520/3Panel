#!/bin/bash
# 3Panel shell message catalog (简体中文).
#
# 由 3pctl 与 install.sh source 加载。每行一个 KEY="VALUE"；
# 面板本身不解析该文件，只有 shell 脚本会读。

# --- 通用 -----------------------------------------------------------------
TXT_SUCCESS_MESSAGE="成功"
TXT_SUCCESSFULLY_MESSAGE="已成功"
TXT_FAIELD_MESSAGE="失败"
TXT_FAILED_MESSAGE="失败"
TXT_IGNORE_MESSAGE="忽略"
TXT_SKIP_MESSAGE="跳过"
TXT_RUN_AS_ROOT="请以 root 用户或使用 sudo 权限运行此脚本"

# --- 安装 -----------------------------------------------------------------
TXT_START_INSTALLATION="======================= 开始安装 ======================="
TXT_PANEL_ALREADY_INSTALLED="3Panel 已安装，请勿重复安装"
TXT_SET_INSTALL_DIR="设置 3Panel 安装目录（默认为 /opt）："
TXT_PROVIDE_FULL_PATH="请提供目录的完整路径"
TXT_SELECTED_INSTALL_PATH="您选择的安装路径为"
TXT_TIMEOUT_USE_DEFAULT_PATH="（已超时，使用默认安装路径 /opt）"
TXT_SET_PANEL_PORT="设置 3Panel 端口"
TXT_SET_PANEL_USER="设置 3Panel 用户名"
TXT_SET_PANEL_PASSWORD="设置 3Panel 密码"
TXT_SET_PANEL_ENTRANCE="设置 3Panel 安全入口（默认为 /）"
TXT_START_PANEL_SERVICE="正在启动 3Panel 服务"
TXT_CONFIGURE_PANEL_SERVICE="正在配置 3Panel 服务"
TXT_SERVICE_RETRY_MSG="服务启动失败，正在重试"
TXT_PANEL_USER="3Panel 用户名"
TXT_PANEL_PASSWORD="3Panel 密码"
TXT_YOUR_PANEL_USERNAME="您的 3Panel 用户名为"
TXT_REMEMBER_YOUR_PASSWORD="请牢记您的密码"
TXT_BROWSER_ACCESS_PANEL="请使用浏览器访问面板"

# --- 3pctl ----------------------------------------------------------------
PANEL_CONTROL_SCRIPT="3Panel 控制脚本"
TXT_PANEL_SERVICE_STATUS="查看服务状态"
TXT_PANEL_SERVICE_START="启动服务"
TXT_PANEL_SERVICE_STOP="停止服务"
TXT_PANEL_SERVICE_RESTART="重启服务"
TXT_PANEL_SERVICE_UNINSTALL="卸载 3Panel"
TXT_PANEL_SERVICE_USER_INFO="查看当前用户信息"
TXT_PANEL_SERVICE_LISTEN_IP="设置监听 IP"
TXT_PANEL_SERVICE_VERSION="查看 3Panel 版本"
TXT_PANEL_SERVICE_UPDATE="更新用户信息"
TXT_PANEL_SERVICE_RESET="重置面板设置"
TXT_PANEL_SERVICE_RESTORE="从备份恢复 3Panel"
TXT_PANEL_SERVICE_START_SUCCESS="服务启动成功"
TXT_PANEL_SERVICE_START_ERROR="服务启动失败"
TXT_PANEL_SERVICE_UNINSTALL_NOTICE="确定要卸载 3Panel 吗？此操作不可撤销（y/n）"
TXT_PANEL_SERVICE_UNINSTALL_START="开始卸载"
TXT_PANEL_SERVICE_UNINSTALL_STOP="正在停止 3Panel 服务"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE="正在删除 3Panel 程序文件"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE_CONFIG="正在删除 3Panel 服务配置"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE_SUCCESS="3Panel 已卸载"
TXT_PANEL_SERVICE_RESTORE_NOTICE="恢复操作将覆盖当前数据，是否继续？（y/n）"
TXT_PANEL_SERVICE_UNSUPPORTED_PARAMETER="不支持的参数，请运行 '3pctl --help' 查看用法"
