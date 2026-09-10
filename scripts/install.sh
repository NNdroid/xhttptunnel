#!/bin/bash
set -e

APP_NAME="xhttptunnel"
GITHUB_REPO="NNdroid/${APP_NAME}"
# Set XHTTPTUNNEL_VERSION to an exact tag (for example,
# v1.0.20260904-8f60417) to pin an installation. The default follows latest.
RELEASE_VERSION="${XHTTPTUNNEL_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/${APP_NAME}"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/${APP_NAME}.service"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
PLAIN="\033[0m"

check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)!${PLAIN}" >&2
    exit 1
  fi
}

get_arch() {
  local arch
  arch=$(uname -m)
  case "${arch}" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    armv7l)  echo "arm" ;;
    i386|i686) echo "386" ;;
    *)
      echo -e "${RED}Error: Unsupported CPU architecture: ${arch}${PLAIN}" >&2
      return 1
      ;;
  esac
}

get_release_download_url() {
  local goarch="$1"
  local release_path

  if [ "${RELEASE_VERSION}" = "latest" ]; then
    release_path="latest/download"
  else
    case "${RELEASE_VERSION}" in
      */*)
        echo -e "${RED}Error: Invalid release tag: ${RELEASE_VERSION}${PLAIN}" >&2
        return 1
        ;;
    esac
    release_path="download/${RELEASE_VERSION}"
  fi

  echo "https://github.com/${GITHUB_REPO}/releases/${release_path}/${APP_NAME}_linux_${goarch}"
}

# Extra parameters for share-URI generation:
#   GEN_URI_PIN   — fixed 6-digit share PIN (default: empty = a random PIN is
#                   generated each time and must be copied from the output).
#   GEN_URI_HOST  — overrides the server public IP/domain in the share URI
#                   (the server config usually only contains the listen port,
#                   not the public address; if unset it falls back to the
#                   your-server-ip placeholder and clients cannot connect).
gen_uri_extra_args() {
  local args=""
  if [ -n "${GEN_URI_PIN:-}" ]; then
    args="${args} -pin ${GEN_URI_PIN}"
  fi
  if [ -n "${GEN_URI_HOST:-}" ]; then
    args="${args} -host ${GEN_URI_HOST}"
  fi
  echo "${args}"
}

install_binary() {
  local goarch
  goarch=$(get_arch)
  mkdir -p "${INSTALL_DIR}"

  if [ -f "./bin/${APP_NAME}_linux_${goarch}" ]; then
    echo -e "${CYAN}--> Using local prebuilt binary (linux/${goarch})...${PLAIN}"
    cp -f "./bin/${APP_NAME}_linux_${goarch}" "${INSTALL_DIR}/${APP_NAME}"
  elif [ -f "./${APP_NAME}" ]; then
    echo -e "${CYAN}--> Using local binary...${PLAIN}"
    cp -f "./${APP_NAME}" "${INSTALL_DIR}/${APP_NAME}"
  elif command -v go >/dev/null 2>&1 && [ -f "./main.go" ]; then
    echo -e "${CYAN}--> Building from source with Go...${PLAIN}"
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "${INSTALL_DIR}/${APP_NAME}" .
  else
    echo -e "${CYAN}--> Downloading ${RELEASE_VERSION} release binary (${goarch})...${PLAIN}"
    local download_url
    download_url=$(get_release_download_url "${goarch}")
    local tmp_bin
    tmp_bin=$(mktemp "/tmp/${APP_NAME}.XXXXXX" 2>/dev/null || echo "/tmp/${APP_NAME}.$$")

    # Check if target path is accidentally a directory
    if [ -d "${INSTALL_DIR}/${APP_NAME}" ]; then
      echo -e "${RED}Error: ${INSTALL_DIR}/${APP_NAME} is a directory! Please remove it first.${PLAIN}" >&2
      rm -f "${tmp_bin}"
      exit 1
    fi

    # Direct download from GitHub Releases
    if ! curl -fL --retry 3 --connect-timeout 15 -o "${tmp_bin}" "${download_url}" || [ ! -s "${tmp_bin}" ]; then
      rm -f "${tmp_bin}"
      echo -e "${RED}Failed to download release binary from GitHub!${PLAIN}"
      echo -e "${YELLOW}Download URL: ${download_url}${PLAIN}"
      echo -e "${YELLOW}Please check network connectivity or disk space.${PLAIN}"
      exit 1
    fi

    chmod +x "${tmp_bin}"
    # Atomically replace target binary using mv (handles running process / ETXTBSY)
    mv -f "${tmp_bin}" "${INSTALL_DIR}/${APP_NAME}"
  fi

  chmod +x "${INSTALL_DIR}/${APP_NAME}"
  echo -e "${GREEN}--> Binary installed to ${INSTALL_DIR}/${APP_NAME}${PLAIN}"
}

get_config_file() {
  local mode="$1"
  if [ "${mode}" == "client" ]; then
    echo "${CONFIG_DIR}/config.client.json"
  else
    echo "${CONFIG_DIR}/config.server.json"
  fi
}

install_config() {
  local mode="$1"
  local config_file
  config_file=$(get_config_file "${mode}")
  mkdir -p "${CONFIG_DIR}"

  if [ ! -f "${config_file}" ] || [ ! -s "${config_file}" ]; then
    local fetched=0
    if [ "${mode}" == "client" ]; then
      if [ -f "./config.client.json" ]; then
        cp -f "./config.client.json" "${config_file}"
        fetched=1
      else
        echo -e "${CYAN}--> Fetching config.client.json from GitHub...${PLAIN}"
        if curl -fsSL --retry 2 "https://raw.githubusercontent.com/${GITHUB_REPO}/main/config.client.json" -o "${config_file}" 2>/dev/null && [ -s "${config_file}" ]; then
          fetched=1
        fi
      fi
      if [ "${fetched}" -ne 1 ]; then
        echo -e "${CYAN}--> Generating default client configuration...${PLAIN}"
        cat <<'EOF' > "${config_file}"
{
  "mode": "client",
  "listen": "tcp://127.0.0.1:1080",
  "server": "https://example.com:8443/stream",
  "target": "127.0.0.1:22",
  "psk": "my-secret-token",
  "sni": "www.bing.com",
  "host": "www.bing.com",
  "alpn": "auto",
  "fingerprint": "",
  "max_conns": 512,
  "dump": false,
  "log_level": "info"
}
EOF
      fi
    else
      if [ -f "./config.server.json" ]; then
        cp -f "./config.server.json" "${config_file}"
        fetched=1
      else
        echo -e "${CYAN}--> Fetching config.server.json from GitHub...${PLAIN}"
        if curl -fsSL --retry 2 "https://raw.githubusercontent.com/${GITHUB_REPO}/main/config.server.json" -o "${config_file}" 2>/dev/null && [ -s "${config_file}" ]; then
          fetched=1
        fi
      fi
      if [ "${fetched}" -ne 1 ]; then
        echo -e "${CYAN}--> Generating default server configuration...${PLAIN}"
        cat <<'EOF' > "${config_file}"
{
  "mode": "server",
  "listen": ":8443",
  "path": "/stream",
  "target": "tcp://127.0.0.1:22",
  "psk": "my-secret-token",
  "selfsign": true,
  "selfsign_cn": "www.bing.com",
  "cert": "",
  "key": "",
  "fallback": "https://www.bing.com",
  "max_sessions": 2000,
  "dump": false,
  "log_level": "info"
}
EOF
      fi
    fi
    echo -e "${GREEN}--> Created ${mode} configuration at ${config_file}${PLAIN}"
  else
    echo -e "${YELLOW}--> Existing configuration preserved at ${config_file}${PLAIN}"
  fi
}

install_systemd() {
  local mode="$1"
  local config_file
  config_file=$(get_config_file "${mode}")
  local desc="Split-HTTP / Meek Tunnel Server"
  if [ "${mode}" == "client" ]; then
    desc="Split-HTTP / Meek Tunnel Client"
  fi

  cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=${APP_NAME} ${desc}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
ExecStart=${INSTALL_DIR}/${APP_NAME} -c ${config_file}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
  echo -e "${GREEN}--> Systemd service registered: ${APP_NAME}.service (${mode} mode)${PLAIN}"
}

do_install() {
  local mode="${1:-server}"
  local config_file
  config_file=$(get_config_file "${mode}")

  check_root
  echo -e "${GREEN}========================================${PLAIN}"
  echo -e "${GREEN}  Installing ${APP_NAME} (${mode} mode)...${PLAIN}"
  echo -e "${GREEN}========================================${PLAIN}"

  install_binary
  install_config "${mode}"
  install_systemd "${mode}"

  systemctl restart "${APP_NAME}" || true

  echo ""
  echo -e "${GREEN}=== Installation Complete (${mode} mode)! ===${PLAIN}"
  echo -e "Configuration: ${CYAN}${config_file}${PLAIN}"
  echo -e "Service Name:  ${CYAN}${APP_NAME}${PLAIN}"
  echo -e "Start:         ${CYAN}systemctl start ${APP_NAME}${PLAIN}"
  echo -e "Status:        ${CYAN}systemctl status ${APP_NAME}${PLAIN}"
  echo -e "View Logs:     ${CYAN}journalctl -u ${APP_NAME} -f${PLAIN}"
  echo ""

  if [ "${mode}" != "client" ]; then
    echo -e "${GREEN}=== Stun Node Sharing URI & QR ===${PLAIN}"
    "${INSTALL_DIR}/${APP_NAME}" gen-uri -c "${config_file}" $(gen_uri_extra_args) || true
    if [ -n "${GEN_URI_PIN:-}" ]; then
      echo -e "${YELLOW}    Share PIN (via GEN_URI_PIN): ${GEN_URI_PIN}${PLAIN}"
    else
      echo -e "${YELLOW}    A random PIN was printed above — note it to import the URI.${PLAIN}"
    fi
  fi
}

do_upgrade() {
  check_root
  echo -e "${YELLOW}========================================${PLAIN}"
  echo -e "${YELLOW}  Upgrading ${APP_NAME}...${PLAIN}"
  echo -e "${YELLOW}========================================${PLAIN}"

  install_binary
  systemctl daemon-reload
  systemctl restart "${APP_NAME}" || true

  echo -e "${GREEN}=== Upgrade Completed! Service restarted. ===${PLAIN}"
  "${INSTALL_DIR}/${APP_NAME}" version || true
}

do_uninstall() {
  check_root
  echo -e "${RED}========================================${PLAIN}"
  echo -e "${RED}  Uninstalling ${APP_NAME}...${PLAIN}"
  echo -e "${RED}========================================${PLAIN}"

  systemctl stop "${APP_NAME}" >/dev/null 2>&1 || true
  systemctl disable "${APP_NAME}" >/dev/null 2>&1 || true
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload

  rm -f "${INSTALL_DIR}/${APP_NAME}"

  echo -e "${GREEN}--> Binary and service removed.${PLAIN}"
  echo -e "${YELLOW}Note: Configuration directory (${CONFIG_DIR}) was kept for safety.${PLAIN}"
  echo -e "To delete configuration permanently: ${CYAN}rm -rf ${CONFIG_DIR}${PLAIN}"
  echo -e "${GREEN}=== ${APP_NAME} Uninstalled Successfully! ===${PLAIN}"
}

do_start() {
  check_root
  systemctl start "${APP_NAME}"
  echo -e "${GREEN}${APP_NAME} started.${PLAIN}"
}

do_stop() {
  check_root
  systemctl stop "${APP_NAME}"
  echo -e "${YELLOW}${APP_NAME} stopped.${PLAIN}"
}

do_restart() {
  check_root
  systemctl restart "${APP_NAME}"
  echo -e "${GREEN}${APP_NAME} restarted.${PLAIN}"
}

do_status() {
  systemctl status "${APP_NAME}"
}

do_logs() {
  journalctl -u "${APP_NAME}" -f -n 50
}

do_uri() {
  local config_file="${CONFIG_DIR}/config.server.json"
  if [ ! -f "${config_file}" ]; then
    config_file="${CONFIG_DIR}/config.json"
  fi
  "${INSTALL_DIR}/${APP_NAME}" gen-uri -c "${config_file}" $(gen_uri_extra_args)
}

action="${1:-install}"
target_mode="${2:-server}"

case "${action}" in
  server)
    action="install"
    target_mode="server"
    ;;
  client)
    action="install"
    target_mode="client"
    ;;
  install-server)
    action="install"
    target_mode="server"
    ;;
  install-client)
    action="install"
    target_mode="client"
    ;;
esac

case "${action}" in
  install)
    do_install "${target_mode}"
    ;;
  upgrade|update)
    do_upgrade
    ;;
  uninstall|remove)
    do_uninstall
    ;;
  start)
    do_start
    ;;
  stop)
    do_stop
    ;;
  restart)
    do_restart
    ;;
  status)
    do_status
    ;;
  logs|log)
    do_logs
    ;;
  uri|qr)
    do_uri
    ;;
  *)
    echo "Usage: $0 {install [server|client]|upgrade|uninstall|start|stop|restart|status|logs|uri}"
    exit 1
    ;;
esac
