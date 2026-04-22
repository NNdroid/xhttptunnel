#!/bin/bash

# ================= 全局参数解析 =================
ACTION=""
CUSTOM_PSK=""
CUSTOM_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --psk)
            CUSTOM_PSK="$2"
            shift 2
            ;;
        --path)
            CUSTOM_PATH="$2"
            shift 2
            ;;
        install|uninstall|update)
            ACTION="$1"
            shift
            ;;
        *)
            echo "错误: 未知的指令或参数 '$1'"
            echo "用法: bash $0 {install|uninstall|update} [--psk <密码>] [--path <路径>]"
            exit 1
            ;;
    esac
done

# ================= 全局权限检测 =================
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    echo "=> 检测到非 root 用户，此脚本需要管理员权限，正在请求 sudo..."
    if ! $SUDO -v; then
        echo "错误：获取 sudo 权限失败，请检查您的密码或权限配置。"
        exit 1
    fi
else
    echo "错误：此脚本需要 root 权限，但系统中未找到 sudo 命令。请切换到 root 用户后重试。"
    exit 1
fi

# ================= 全局变量定义 =================
REPO="NNdroid/xhttptunnel"
BIN_PATH="/usr/local/bin/xhttptunnel"
CONFIG_DIR="/usr/local/etc/xhttptunnel"
CERT_PATH="$CONFIG_DIR/crt.crt"
KEY_PATH="$CONFIG_DIR/crt.key"
SERVICE_PATH="/etc/systemd/system/xhttptunnel.service"

# ================= 依赖检查与安装 =================
install_dependencies() {
    if command -v curl >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
        echo "=> 系统依赖检查通过 (curl, openssl 已安装)。"
        return 0
    fi

    echo "=> 正在检查并安装必要的依赖 (curl, openssl, ca-certificates)..."

    local os_type
    os_type=$(uname -s | tr '[:upper:]' '[:lower:]')

    if [ "$os_type" != "linux" ]; then
        echo "=> 非 Linux 系统，跳过自动安装依赖，请确保已手动安装 curl 和 openssl。"
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        echo "=> 检测到 Debian/Ubuntu (apt-get)，正在执行安装..."
        $SUDO apt-get update -qq
        $SUDO apt-get install -y curl openssl ca-certificates >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        echo "=> 检测到 Fedora/RHEL8+ (dnf)，正在执行安装..."
        $SUDO dnf install -y curl openssl ca-certificates >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        echo "=> 检测到 CentOS/RHEL7 及更低版本 (yum)，正在执行安装..."
        $SUDO yum install -y curl openssl ca-certificates >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        echo "=> 检测到 Arch Linux (pacman)，正在执行安装..."
        $SUDO pacman -Sy --noconfirm curl openssl ca-certificates >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        echo "=> 检测到 Alpine Linux (apk)，正在执行安装..."
        $SUDO apk add --no-cache curl openssl ca-certificates >/dev/null 2>&1
    else
        echo "=> 警告：未检测到受支持的包管理器，请手动确认 curl 和 openssl 已安装。"
    fi
}

# ================= 核心功能函数 =================
download_latest_xhttptunnel() {
    local os
    local arch
    local ext=""
    local filename
    local download_url
    local tmp_file

    echo "=> 正在检测操作系统和架构..."

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    if [[ "$os" == *mingw* || "$os" == *cygwin* || "$os" == *msys* ]]; then
        os="windows"
        ext=".exe"
    elif [[ "$os" != "linux" && "$os" != "darwin" ]]; then
        echo "错误：不支持的操作系统: $os"
        return 1
    fi

    arch=$(uname -m)
    case "$arch" in
        x86_64 | amd64)
            arch="amd64"
            ;;
        aarch64 | arm64)
            arch="arm64"
            ;;
        armv* | arm)
            arch="arm"
            ;;
        *)
            echo "错误：不支持的系统架构: $arch"
            return 1
            ;;
    esac

    filename="xhttptunnel-${os}-${arch}${ext}"
    download_url="https://github.com/${REPO}/releases/latest/download/${filename}"
    tmp_file="/tmp/${filename}"

    echo "=> 匹配到的版本为: ${filename}"
    echo "=> 正在从 ${download_url} 下载..."

    if ! curl -L -f -o "$tmp_file" "$download_url"; then
        echo "错误：下载失败，请检查网络或确认该架构的 release 存在 ($download_url)"
        return 1
    fi

    chmod +x "$tmp_file"

    echo "=> 准备安装到 ${BIN_PATH}..."
    local dest_dir
    dest_dir=$(dirname "$BIN_PATH")

    if [ -w "$dest_dir" ]; then
        mv "$tmp_file" "$BIN_PATH"
        chmod +x "$BIN_PATH"
    else
        echo "=> 正在使用管理员权限移动文件..."
        $SUDO mv "$tmp_file" "$BIN_PATH"
        $SUDO chmod +x "$BIN_PATH"
    fi

    if [ -f "$BIN_PATH" ]; then
        echo "=> 安装成功！可执行文件已放置在: $BIN_PATH"
    else
        echo "错误：移动文件到 $BIN_PATH 失败。"
        return 1
    fi
}

remove_xhttptunnel() {
    echo "=> 准备卸载核心程序..."

    if [ ! -f "$BIN_PATH" ]; then
        echo "=> 提示：xhttptunnel 未安装在 $BIN_PATH，无需执行删除操作。"
        return 0
    fi

    local dest_dir
    dest_dir=$(dirname "$BIN_PATH")

    if [ -w "$dest_dir" ] && [ -w "$BIN_PATH" ]; then
        rm "$BIN_PATH"
    else
        $SUDO rm "$BIN_PATH"
    fi

    if [ ! -f "$BIN_PATH" ]; then
        echo "=> 卸载成功！已彻底清理: $BIN_PATH"
    else
        echo "错误：删除 $BIN_PATH 失败，请检查文件占用或权限。"
        return 1
    fi
}

setup_xhttptunnel_env() {
    echo "=> 正在配置 xhttptunnel 环境..."

    if [ ! -d "$CONFIG_DIR" ]; then
        echo "=> 检测到配置目录不存在，正在创建: $CONFIG_DIR"
        $SUDO mkdir -p "$CONFIG_DIR"
    fi

    if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
        echo "=> 提示：证书已存在 ($CERT_PATH)，跳过生成步骤。"
    else
        echo "=> 正在生成自签 TLS 证书..."
        if $SUDO openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$KEY_PATH" -out "$CERT_PATH" \
            -subj "/C=US/ST=Washington/L=Seattle/O=Amazon.com, Inc./OU=Amazon Web Services/CN=ec2.amazonaws.com"  >/dev/null 2>&1; then
            echo "=> 证书生成成功！"
        else
            echo "错误：证书生成失败。请确保系统中已安装 openssl。"
            return 1
        fi
    fi

    # ================= 动态应用 PSK 和 Path =================
    local final_path
    if [ -n "$CUSTOM_PATH" ]; then
        final_path="$CUSTOM_PATH"
        # 确保以 / 开头，提升容错率
        [[ "$final_path" != /* ]] && final_path="/${final_path}"
        echo "=> 使用指定的路径: ${final_path}"
    else
        final_path="/$(openssl rand -hex 2)/$(openssl rand -hex 2)"
        echo "=> 已自动生成随机 2 层路径: ${final_path}"
    fi

    local final_psk
    if [ -n "$CUSTOM_PSK" ]; then
        final_psk="$CUSTOM_PSK"
        echo "=> 使用指定的 PSK: ${final_psk}"
    else
        final_psk=$(openssl rand -hex 6)
        echo "=> 已自动生成随机 12 位 PSK 密钥: ${final_psk}"
    fi
    # ========================================================

    echo "=> 正在写入 systemd 服务文件到: $SERVICE_PATH"
    
    $SUDO tee "$SERVICE_PATH" > /dev/null << EOF
[Unit]
Description=xHTTP Tunnel Server
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xhttptunnel -mode server -default-target tcp://127.0.0.1:22 -listen :443 -path ${final_path} -cert /usr/local/etc/xhttptunnel/crt.crt -key /usr/local/etc/xhttptunnel/crt.key -psk ${final_psk} -loglevel warn

Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=10

LimitNOFILE=1048576
LimitNPROC=1048576
MemoryHigh=512M
MemoryMax=1G
OOMScoreAdjust=100

[Install]
WantedBy=multi-user.target
EOF

    echo "=> 正在重载 systemd 守护进程以应用新服务..."
    $SUDO systemctl daemon-reload

    echo "======================================================"
    echo "=> xhttptunnel 基础环境已配置完成！"
    echo "=> 【重要】请记录以下信息用于客户端配置："
    echo "   当前路径: ${final_path}"
    echo "   PSK 密钥: ${final_psk}"
    echo "------------------------------------------------------"
    echo "=> 常用操作命令："
    echo "   启动服务: $SUDO systemctl start xhttptunnel"
    echo "   开机自启: $SUDO systemctl enable xhttptunnel"
    echo "   查看状态: $SUDO systemctl status xhttptunnel"
    echo "   查看日志: $SUDO journalctl -u xhttptunnel -f"
    echo "======================================================"
}

clear_xhttptunnel_env() {
    echo "=> 准备清理 xhttptunnel 运行环境..."

    if systemctl list-unit-files | grep -q "^xhttptunnel.service"; then
        echo "=> 正在停止并禁用 xhttptunnel 服务..."
        $SUDO systemctl stop xhttptunnel
        $SUDO systemctl disable xhttptunnel
    else
        echo "=> 提示：未检测到注册的 xhttptunnel 服务状态。"
    fi

    if [ -f "$SERVICE_PATH" ]; then
        echo "=> 正在删除系统服务配置文件: $SERVICE_PATH"
        $SUDO rm -f "$SERVICE_PATH"
        echo "=> 重新加载 systemd 守护进程..."
        $SUDO systemctl daemon-reload
    fi

    if [ -d "$CONFIG_DIR" ]; then
        echo "=> 正在删除配置目录及其包含的证书: $CONFIG_DIR"
        $SUDO rm -rf "$CONFIG_DIR"
    else
        echo "=> 提示：配置目录已不存在 ($CONFIG_DIR)。"
    fi

    echo "======================================================"
    echo "=> 环境清理完毕！"
    echo "======================================================"
}

# ================= 主程序入口 =================
if [ -z "$ACTION" ]; then
    echo "用法: bash $0 {install|uninstall|update} [--psk <密码>] [--path <路径>]"
    echo "  install   - 安装依赖、下载最新版本、配置证书和服务，并启动"
    echo "  uninstall - 停止服务、删除二进制文件、清理证书和配置"
    echo "  update    - 安装依赖、停止当前服务、更新二进制文件并重启服务"
    exit 1
fi

case "$ACTION" in
    install)
        echo "======================================================"
        echo "=> 开始执行安装流程..."
        echo "======================================================"
        install_dependencies
        download_latest_xhttptunnel
        setup_xhttptunnel_env
        
        echo "=> 正在启动并设置开机自启 xhttptunnel 服务..."
        $SUDO systemctl enable --now xhttptunnel
        
        echo "=> xhttptunnel 安装并启动完成！"
        ;;
        
    uninstall)
        echo "======================================================"
        echo "=> 开始执行卸载流程..."
        echo "======================================================"
        
        if systemctl list-unit-files | grep -q "^xhttptunnel.service"; then
            echo "=> 正在停止并禁用服务..."
            $SUDO systemctl disable --now xhttptunnel
        fi
        
        remove_xhttptunnel
        clear_xhttptunnel_env
        
        echo "=> xhttptunnel 已完全卸载！"
        ;;
        
    update)
        echo "======================================================"
        echo "=> 开始执行更新流程..."
        echo "======================================================"
        install_dependencies
        
        if systemctl is-active --quiet xhttptunnel; then
            echo "=> 正在停止运行中的 xhttptunnel 服务..."
            $SUDO systemctl stop xhttptunnel
        fi
        
        download_latest_xhttptunnel
        
        if systemctl list-unit-files | grep -q "^xhttptunnel.service"; then
            echo "=> 正在重启 xhttptunnel 服务..."
            $SUDO systemctl start xhttptunnel
            echo "=> 更新完成！服务已重新启动。"
        else
            echo "=> 更新完成！(提示：未检测到系统服务，请确认是否需要执行 install)"
        fi
        ;;
        
    *)
        echo "错误：未知的指令 '$ACTION'"
        echo "用法: bash $0 {install|uninstall|update} [--psk <密码>] [--path <路径>]"
        exit 1
        ;;
esac