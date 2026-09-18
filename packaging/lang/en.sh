#!/bin/bash
# 3Panel shell message catalog (English).
#
# Sourced by 3pctl and install.sh. Keep one KEY="VALUE" per line; the panel
# itself never parses this file — only the shell scripts do.

# --- generic ---------------------------------------------------------------
TXT_SUCCESS_MESSAGE="Success"
TXT_SUCCESSFULLY_MESSAGE="Successfully"
TXT_FAIELD_MESSAGE="Failed"
TXT_FAILED_MESSAGE="Failed"
TXT_IGNORE_MESSAGE="Ignore"
TXT_SKIP_MESSAGE="Skip"
TXT_RUN_AS_ROOT="Please run this script as root or with sudo permissions"

# --- install ---------------------------------------------------------------
TXT_START_INSTALLATION="======================= Starting Installation ======================="
TXT_PANEL_ALREADY_INSTALLED="3Panel is already installed, please do not install again"
TXT_SET_INSTALL_DIR="Set 3Panel installation directory (default is /opt): "
TXT_PROVIDE_FULL_PATH="Please provide the full path of the directory"
TXT_SELECTED_INSTALL_PATH="The installation path you selected is"
TXT_TIMEOUT_USE_DEFAULT_PATH="(Timeout set, using default installation path /opt)"
TXT_SET_PANEL_PORT="Set 3Panel port"
TXT_SET_PANEL_USER="Set 3Panel username"
TXT_SET_PANEL_PASSWORD="Set 3Panel password"
TXT_SET_PANEL_ENTRANCE="Set 3Panel entrance (default /)"
TXT_START_PANEL_SERVICE="Starting 3Panel service"
TXT_CONFIGURE_PANEL_SERVICE="Configuring 3Panel service"
TXT_SERVICE_RETRY_MSG="Service failed to start, retrying"
TXT_PANEL_USER="3Panel username"
TXT_PANEL_PASSWORD="3Panel password"
TXT_YOUR_PANEL_USERNAME="Your 3Panel username is"
TXT_REMEMBER_YOUR_PASSWORD="Please remember your password"
TXT_BROWSER_ACCESS_PANEL="Please access the panel in your browser"

# --- 3pctl ----------------------------------------------------------------
PANEL_CONTROL_SCRIPT="3Panel control script"
TXT_PANEL_SERVICE_STATUS="Show the service status"
TXT_PANEL_SERVICE_START="Start the service"
TXT_PANEL_SERVICE_STOP="Stop the service"
TXT_PANEL_SERVICE_RESTART="Restart the service"
TXT_PANEL_SERVICE_UNINSTALL="Uninstall 3Panel"
TXT_PANEL_SERVICE_USER_INFO="Show the current user information"
TXT_PANEL_SERVICE_LISTEN_IP="Set the listening IP"
TXT_PANEL_SERVICE_VERSION="Show the 3Panel version"
TXT_PANEL_SERVICE_UPDATE="Update the user information"
TXT_PANEL_SERVICE_RESET="Reset the panel settings"
TXT_PANEL_SERVICE_RESTORE="Restore 3Panel from a backup"
TXT_PANEL_SERVICE_START_SUCCESS="Service started successfully"
TXT_PANEL_SERVICE_START_ERROR="Failed to start the service"
TXT_PANEL_SERVICE_UNINSTALL_NOTICE="Are you sure you want to uninstall 3Panel? This cannot be undone (y/n)"
TXT_PANEL_SERVICE_UNINSTALL_START="Starting uninstallation"
TXT_PANEL_SERVICE_UNINSTALL_STOP="Stopping 3Panel services"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE="Removing 3Panel binaries"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE_CONFIG="Removing 3Panel service configuration"
TXT_PANEL_SERVICE_UNINSTALL_REMOVE_SUCCESS="3Panel has been uninstalled"
TXT_PANEL_SERVICE_RESTORE_NOTICE="Restoring will overwrite the current data. Continue? (y/n)"
TXT_PANEL_SERVICE_UNSUPPORTED_PARAMETER="Unsupported parameter, run '3pctl --help' for usage"
