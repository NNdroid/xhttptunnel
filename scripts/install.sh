#!/bin/bash
set -euo pipefail

umask 077

APP_NAME="xhttptunnel"
GITHUB_REPO="NNdroid/${APP_NAME}"
# Set XHTTPTUNNEL_VERSION to an exact tag (for example,
# v1.0.20260904-8f60417) to pin an installation. The default follows latest.
RELEASE_VERSION="${XHTTPTUNNEL_VERSION:-latest}"
# The install locations are overridable so the installer can be exercised
# against a scratch directory without touching the live system.
INSTALL_DIR="${XHTTPTUNNEL_INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${XHTTPTUNNEL_CONFIG_DIR:-/etc/${APP_NAME}}"
SYSTEMD_DIR="${XHTTPTUNNEL_SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_FILE="${SYSTEMD_DIR}/${APP_NAME}.service"

# Color variables carry a real ESC byte. printf '%s' and bare printf formats
# do not interpret "\033", which is what printed the literal "\033[31m" text
# in the wizard prompts. Color is suppressed entirely when neither fd 1 nor fd
# 2 is a terminal so piped output stays clean.
ESC="$(printf '\033')"
if [ -t 1 ] || [ -t 2 ]; then
  RED="${ESC}[31m"
  GREEN="${ESC}[32m"
  YELLOW="${ESC}[33m"
  CYAN="${ESC}[36m"
  BOLD="${ESC}[1m"
  PLAIN="${ESC}[0m"
else
  RED=""
  GREEN=""
  YELLOW=""
  CYAN=""
  BOLD=""
  PLAIN=""
fi

# ---------------------------------------------------------------------------
# Resolved configuration spec.
#
# Every value below is resolved once, in this precedence order:
#     command-line flag  >  environment variable  >  interactive prompt  >  default
# collect_config() fills the ones the caller did not supply, and every writer
# reads from this table. This table is the single source of truth for what an
# installation receives; the sample config.server.json / config.client.json in
# the repository are human-readable documentation of the same field set.
# ---------------------------------------------------------------------------
CFG_ACTION="install"
CFG_MODE="server"

# Network / identity
CFG_HOST=""                        # public IP or domain: share URI + client URL
CFG_HOST_SOURCE="unset"            # flag | env | manual | auto | default
CFG_HOST_AUTO="on"                 # --no-auto-ip disables the public-IP probe
CFG_PORT="443"
CFG_PATH="/stream"
CFG_LISTEN=""                      # server bind address; empty = ":<port>"
CFG_SERVER_URL=""                  # client upstream URL; empty = derived
CFG_SERVER_TARGET="tcp://127.0.0.1:22"
CFG_CLIENT_TARGET="127.0.0.1:22"
CFG_CLIENT_LISTEN="tcp://127.0.0.1:1080"

# TLS camouflage
CFG_SELF_SIGN="true"
CFG_SELF_SIGN_CN="www.bing.com"
CFG_FALLBACK="https://www.bing.com"
CFG_SNI=""                         # client TLS SNI + HTTP Host; empty = derived
CFG_FINGERPRINT=""

# Authentication
CFG_PSK=""
CFG_PSK_GIVEN="false"              # --psk or XHTTPTUNNEL_PSK was supplied
CFG_PSK_MODE="auto"                # auto | manual | open
CFG_PSK_SOURCE="default"           # auto | flag | env | manual | open

# Target policy
CFG_ALLOW_PUBLIC_TARGETS="false"   # false = restrict to loopback only
CFG_ALLOWED_TARGETS=""             # explicit comma-separated allowed_targets

# Limits / tuning
CFG_MAX_SESSIONS=2000
CFG_MAX_SESSIONS_PER_IP=50
CFG_MAX_CONNS=512
CFG_CHUNK_SIZE_KB=256
CFG_IDLE_TIMEOUT=900
CFG_HEALTH_PATH=""
CFG_MIN_PROTO_VERSION=0
CFG_TRUST_PROXY_HEADERS="false"
CFG_ALPN="auto"
CFG_STREAM_MODE="auto"
CFG_LOG_LEVEL="info"
CFG_DUMP="false"

# TCP Brutal (Linux kernel module only; the block is inert on other platforms)
CFG_BRUTAL_ENABLE="false"
CFG_BRUTAL_RATE=0
CFG_BRUTAL_CWND_GAIN=0             # 0 = engine default 20 (tenths, so 20 = 2.0x)
CFG_BRUTAL_GROUP_ID=0
CFG_BRUTAL_GROUP_FROM_REMOTE="false"
CFG_BRUTAL_BW_EXCHANGE="false"
CFG_BRUTAL_BW_ADVERTISE=0
CFG_BRUTAL_BW_INTERVAL=60

# Behaviour switches
INTERACTIVE=1
ASSUME_YES="false"
FORCE_OVERWRITE="false"
FLAG_SET=""                        # names of options given explicitly on the CLI

die() { echo -e "${RED}Error: $*${PLAIN}" >&2; exit 1; }
warn() { echo -e "${YELLOW}$*${PLAIN}"; }
info() { echo -e "${CYAN}$*${PLAIN}"; }
ok() { echo -e "${GREEN}$*${PLAIN}"; }

check_root() {
  if [ "$EUID" -ne 0 ]; then
    die "Please run as root (sudo)! Use XHTTPTUNNEL_CONFIG_DIR and friends to install outside the system paths"
  fi
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

is_tty() { [ -t 0 ] && [ -t 1 ]; }

# mark_flag records that a value came from the command line, so a later
# environment override does not clobber an explicit flag.
mark_flag() { FLAG_SET="${FLAG_SET} $1"; }
has_flag() { [[ " ${FLAG_SET} " == *" $1 "* ]]; }

# Boolean flags require no value, but `--selfsign true` is how operators often
# write them. bool_value/to_bool let parse_args consume one adjacent
# recognizable boolean so both spellings work; any other adjacent token stays
# positional and is rejected instead of being silently dropped.
bool_value() {
  case "${1:-}" in
    true|false|TRUE|False|FALSE|True|1|0|yes|no|YES|NO|Yes|No|on|off|ON|OFF) return 0 ;;
    *) return 1 ;;
  esac
}
to_bool() {
  case "${1:-}" in
    true|TRUE|True|1|yes|YES|Yes|on|ON) echo true ;;
    *) echo false ;;
  esac
}

# PROMPT_REPLY carries the answer back out of prompt_input / prompt_yesno.
#
# The functions must NOT be invoked inside command substitution
# (answer="$(prompt_input ...)"). A $() subshell disables readline, so "read"
# there has no line editing at all: backspace is echoed as a literal ^H and the
# operator cannot correct a typo, only Ctrl-C out of a half-entered secret.
# Returning through a global instead of stdout keeps "read" running in the main
# shell body, where readline and normal editing are live.
PROMPT_REPLY=""

# prompt_input asks "label [default]:" and stores the answer in PROMPT_REPLY,
# falling back to the default on an empty line or on EOF (a drained pipe must
# not abort the run).
prompt_input() {
  local label="$1" default="$2" answer
  # The prompt goes to fd 2 so it never gets mixed into any captured output.
  if [ -n "${default}" ]; then
    printf '? %s [%s]: ' "${YELLOW}${label}${PLAIN}" "${CYAN}${default}${PLAIN}" >&2
  else
    printf '? %s: ' "${YELLOW}${label}${PLAIN}" >&2
  fi
  if IFS= read -r answer; then
    answer="${answer}"
  else
    answer=""
  fi
  PROMPT_REPLY="${answer:-${default}}"
}

# prompt_yesno asks a yes/no question; "$2" is y or n for the default answer.
prompt_yesno() {
  local label="$1" default="$2" answer hint reply
  if [ "${default}" = "y" ]; then hint="Y/n"; else hint="y/N"; fi
  printf '? %s [%s]: ' "${YELLOW}${label}${PLAIN}" "${CYAN}${hint}${PLAIN}" >&2
  if IFS= read -r answer; then
    answer="${answer}"
  else
    answer=""
  fi
  reply="${answer:-${default}}"
  reply="$(printf '%s' "${reply}" | tr '[:upper:]' '[:lower:]')"
  case "${reply}" in
    y|yes|1|true) PROMPT_REPLY="true" ;;
    *) PROMPT_REPLY="false" ;;
  esac
}

# json_escape makes a value safe inside a JSON string literal. The script has
# no jq dependency; these five escapes cover what a config value can contain.
json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/}
  s=${s//$'\t'/\\t}
  printf '%s' "${s}"
}

# trim_space strips leading and trailing whitespace in place of a sed/sed -e
# dependency; the two expansions peel the outer run of blanks.
trim_space() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "${s}"
}

# Address checks are deliberately permissive: an IPv6 literal is anything made
# of hex digits and colons (optionally inside brackets).
is_valid_ipv4() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }
is_valid_ipv6() { [[ "$1" =~ ^[0-9a-fA-F:.]+$ ]] && [[ "$1" == *:* ]]; }

# is_valid_target_host accepts a hostname, an IPv4/IPv6 literal, or a bracketed
# IPv6 literal. Brackets are the only unambiguous way to write an address that
# already contains colons, so an unbracketed colon is a formatting error.
is_valid_target_host() {
  local h="$1"
  [ -z "${h}" ] && return 0
  [ "${h}" = "*" ] && return 0
  case "${h}" in
    \[*\])
      h="${h#[}"
      h="${h%\]}"
      if is_valid_ipv6 "${h}"; then return 0; else return 1; fi
      ;;
    *:*)
      return 1
      ;;
  esac
  [[ "${h}" =~ ^[A-Za-z0-9._-]+$ ]]
}

# validate_allowed_target_entry enforces the allowed_targets grammar. The
# generator is stricter than the runtime matcher, and this function matches the
# generator so a bad entry fails at install time instead of at service boot.
validate_allowed_target_entry() {
  local entry="$1" scheme rest host port
  entry="$(trim_space "${entry}")"
  if [ -z "${entry}" ]; then
    die "allowed_targets has an empty entry; use a comma-separated list with no blank items"
  fi
  case "${entry}" in
    *://*)
      scheme="$(trim_space "${entry%%://*}")"
      entry="$(trim_space "${entry#*://}")"
      case "${scheme}" in
        tcp|TCP|udp|UDP) ;;
        *) die "allowed_targets entry '${1}': unknown scheme '${scheme}', only tcp:// and udp:// are dialable" ;;
      esac
      if [ -z "${entry}" ]; then
        die "allowed_targets entry '${1}' has a scheme but no address"
      fi
      ;;
  esac
  case "${entry}" in
    '*') return 0 ;;
    *:*)
      case "${entry}" in
        \[*)
          # Brackets are the only unambiguous form for an address that already
          # contains colons, so a bare IPv6 literal is a formatting error.
          local bare="${entry%%]*}" after="${entry#*]}"
          bare="${bare#[}"
          if ! is_valid_ipv6 "${bare}"; then
            die "allowed_targets entry '${1}': invalid IPv6 address in '${entry}'"
          fi
          if [ -z "${after}" ]; then
            port=""
          elif [ "${after:0:1}" = ":" ]; then
            port="${after:1}"
          else
            die "allowed_targets entry '${1}': expected ']' or ']:port' after the IPv6 address, got '${after}'"
          fi
          host="[${bare}]"
          ;;
        *)
          host="${entry%:*}"
          port="${entry##*:}"
          ;;
      esac
      if ! is_valid_target_host "${host}"; then
        die "allowed_targets entry '${1}': invalid host '${host}' (wrap an IPv6 address in brackets, e.g. [::1]:22)"
      fi
      if [ -n "${port}" ]; then
        case "${port}" in
          *[!0-9]*) die "allowed_targets entry '${1}': port '${port}' is not a number" ;;
        esac
        if [ "${port}" -lt 1 ] || [ "${port}" -gt 65535 ]; then
          die "allowed_targets entry '${1}': port must be 1-65535, got '${port}'"
        fi
      fi
      return 0
      ;;
    *)
      die "allowed_targets entry '${1}' must be host:port, :port, host:, [host] or *"
      ;;
  esac
}

# validate_allowed_targets walks a comma-separated list. The emptiness check
# strips the spaces first, because an operator almost always types "a , b".
validate_allowed_targets() {
  local list="$1" nospace entry
  nospace="$(printf '%s' "${list}" | tr -d '[:space:]')"
  case "${nospace}" in
    ''|','*|*','|*,,*)
      die "allowed_targets list '${list}' has an empty entry; separate entries with a single comma"
      ;;
  esac
  # The emptiness check above makes word splitting safe here: with no empty
  # segment present, splitting on commas yields one word per entry. noglob
  # keeps a lone "*" from expanding to the current directory.
  local IFS=,
  set -o noglob
  for entry in ${list}; do
    validate_allowed_target_entry "${entry}"
  done
  set +o noglob
}

host_bracketed() {
  if is_valid_ipv6 "$1"; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
}

# ---------------------------------------------------------------------------
# Public IP discovery
# ---------------------------------------------------------------------------

# detect_public_ip tries a short chain of well-known echo services and prints
# the first answer that looks like an address. Each endpoint gets 5 seconds;
# the whole chain is best-effort and never fails the install.
detect_public_ip() {
  local endpoints=(
    "https://api.ipify.org"
    "https://ifconfig.me/ip"
    "https://ip.sb/ip"
    "https://myip.dnsabr.com"
    "https://api.ip.sb/ip"
    "https://ifconfig.co"
  )
  local endpoint out
  for endpoint in "${endpoints[@]}"; do
    out=$(curl -fsSL --max-time 5 --connect-timeout 3 "${endpoint}" 2>/dev/null || true)
    # Strip everything that cannot be part of an address (some services append
    # a newline or a trailing slash).
    out="${out//[!0-9a-fA-F:.]/}"
    if is_valid_ipv4 "${out}" || is_valid_ipv6 "${out}"; then
      printf '%s' "${out}"
      return 0
    fi
  done
  return 1
}

# resolve_host fills CFG_HOST. Order: --host, XHTTPTUNNEL_HOST / GEN_URI_HOST,
# the interactive answer, the automatic probe, then an empty placeholder.
resolve_host() {
  if [ -n "${CFG_HOST}" ]; then
    # Already supplied by a flag or the environment; resolve_host only owns
    # the "nothing was given" path.
    return 0
  fi
  if [ -n "${GEN_URI_HOST:-}" ]; then
    CFG_HOST="${GEN_URI_HOST}"
    CFG_HOST_SOURCE="env"
    return 0
  fi

  if [ "${INTERACTIVE}" -eq 1 ]; then
    printf "  ${PLAIN}(${CYAN}a${PLAIN} = auto-detect the public IP)\n" >&2
    local answer
    prompt_input "Public host (IP or domain)" "a"
    answer="${PROMPT_REPLY}"
    if [ "${answer}" != "a" ] && [ "${answer}" != "auto" ] && [ -n "${answer}" ]; then
      CFG_HOST="${answer}"
      CFG_HOST_SOURCE="manual"
      return 0
    fi
  fi
  CFG_HOST_SOURCE="auto"

  if [ "${CFG_HOST_AUTO}" = "on" ]; then
    local detected
    if detected="$(detect_public_ip)"; then
      CFG_HOST="${detected}"
      ok "--> Auto-detected public IP: ${CFG_HOST}"
      return 0
    fi
    warn "--> Could not auto-detect the public IP; check the network, or pass --host <ip-or-domain>"
  else
    info "--> Skipped public IP detection (--no-auto-ip)"
  fi

  # CFG_HOST stays empty: the client URL then carries your-server-ip and
  # gen-uri prints YOUR_SERVER_IP, both loud enough that nobody ships them.
  CFG_HOST_SOURCE="default"
}

# ---------------------------------------------------------------------------
# PSK
# ---------------------------------------------------------------------------

# generate_psk produces 256 bits of hex. /dev/urandom is the primary source
# (the original installer relied on it); openssl is the fallback for shells
# without od or a urandom node.
generate_psk() {
  local out=""
  out=$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || true)
  if [[ ! "${out}" =~ ^[0-9a-f]{64}$ ]] && command -v openssl >/dev/null 2>&1; then
    out=$(openssl rand -hex 32 2>/dev/null || true)
  fi
  [[ "${out}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "${out}"
}

# resolve_psk fills CFG_PSK. Server mode invents its own secret; client mode
# must not, because a freshly generated one would never authenticate.
resolve_psk() {
  if [ "${CFG_PSK_GIVEN}" = "true" ]; then
    CFG_PSK_SOURCE="flag"
    [ -z "${CFG_PSK}" ] && { CFG_PSK_MODE="open"; CFG_PSK_SOURCE="open"; }
    return 0
  fi
  if [ "${CFG_PSK_MODE}" = "open" ]; then
    CFG_PSK=""
    CFG_PSK_SOURCE="open"
    return 0
  fi

  if [ "${INTERACTIVE}" -ne 1 ]; then
    if [ "${CFG_MODE}" = "server" ] || [ "${CFG_PSK_MODE}" = "auto" ]; then
      CFG_PSK="$(generate_psk)" || die "failed to generate a 256-bit PSK"
      CFG_PSK_SOURCE="auto"
    else
      CFG_PSK=""
      CFG_PSK_MODE="open"
      CFG_PSK_SOURCE="open"
      warn "--> Client mode with no PSK: the client will connect unauthenticated"
    fi
    return 0
  fi

  local label="PSK token"
  local dflt="a" answer=""
  if [ "${CFG_MODE}" = "client" ]; then
    label="Server PSK (must match the server config psk)"
    # A freshly generated secret would never authenticate against the server,
    # so client mode defaults to typing the real one instead.
    dflt="m"
  fi
  if [ "${dflt}" = "m" ]; then
    printf "  ${PLAIN}(${CYAN}m${PLAIN} = manual input)\n" >&2
    printf "  ${PLAIN}(${CYAN}a${PLAIN} = auto-generate; test only, will not match any server)\n" >&2
  else
    printf "  ${PLAIN}(${CYAN}a${PLAIN} = auto-generate a 256-bit random token)\n" >&2
    printf "  ${PLAIN}(${CYAN}m${PLAIN} = manual input)\n" >&2
  fi
  printf "  ${PLAIN}(${CYAN}s${PLAIN} = leave empty for explicit open mode)\n" >&2
  prompt_input "${label}" "${dflt}"
  answer="${PROMPT_REPLY}"
  case "${answer}" in
    a|auto)
      CFG_PSK="$(generate_psk)" || die "failed to generate a 256-bit PSK"
      CFG_PSK_MODE="auto"
      CFG_PSK_SOURCE="auto"
      ;;
    m|manual)
      # m means "I will type the secret now", so the secret comes on the next
      # line; storing the literal "m" would lock the operator out.
      prompt_input "${label} (Enter = leave empty for open mode)" ""
      answer="${PROMPT_REPLY}"
      if [ -z "${answer}" ]; then
        CFG_PSK=""
        CFG_PSK_MODE="open"
        CFG_PSK_SOURCE="open"
      else
        CFG_PSK="${answer}"
        CFG_PSK_MODE="manual"
        CFG_PSK_SOURCE="manual"
      fi
      ;;
    s|skip|open)
      CFG_PSK=""
      CFG_PSK_MODE="open"
      CFG_PSK_SOURCE="open"
      ;;
    "")
      CFG_PSK=""
      CFG_PSK_MODE="open"
      CFG_PSK_SOURCE="open"
      ;;
    *)
      CFG_PSK="${answer}"
      CFG_PSK_MODE="manual"
      CFG_PSK_SOURCE="manual"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Derived values
# ---------------------------------------------------------------------------

derive_server_url() {
  if [ -n "${CFG_SERVER_URL}" ]; then
    printf '%s' "${CFG_SERVER_URL}"
    return 0
  fi
  local h="${CFG_HOST}"
  [ -z "${h}" ] && h="your-server-ip"
  printf 'https://%s:%s%s' "$(host_bracketed "${h}")" "${CFG_PORT}" "${CFG_PATH}"
}

derive_listen() {
  if [ -n "${CFG_LISTEN}" ]; then
    printf '%s' "${CFG_LISTEN}"
  else
    printf ':%s' "${CFG_PORT}"
  fi
}

# client_sni resolves the client's TLS SNI and HTTP Host. An explicit --sni
# wins; otherwise a self-signed server implies its own CN, and a CDN-terminated
# deployment leaves it empty so the value derives from the server URL.
client_sni() {
  if [ -n "${CFG_SNI}" ]; then
    printf '%s' "${CFG_SNI}"
    return 0
  fi
  if [ "${CFG_SELF_SIGN}" = "true" ]; then
    printf '%s' "${CFG_SELF_SIGN_CN}"
    return 0
  fi
  printf ''
}

allowed_targets_json() {
  local out="" entry
  # An explicitly typed list wins outright, so the operator can express the
  # middle ground that neither of the two presets covers.
  if [ -n "${CFG_ALLOWED_TARGETS}" ]; then
    local IFS=,
    set -o noglob
    for entry in ${CFG_ALLOWED_TARGETS}; do
      entry="$(trim_space "${entry}")"
      if [ -n "${out}" ]; then
        out="${out}, "
      fi
      out="${out}\"$(json_escape "${entry}")\""
    done
    set +o noglob
    printf '[%s]' "${out}"
    return 0
  fi
  if [ "${CFG_ALLOW_PUBLIC_TARGETS}" = "true" ]; then
    printf '[]'
  else
    # The tcp:// and udp:// prefixes carry the same policy as the bare
    # "127.0.0.1:" / "localhost:" forms and show the operators the syntax:
    # "tcp://192.168.1.10:" reaches that host over TCP only, "udp://:53" any
    # host's UDP DNS. An entry without a scheme admits either protocol.
    printf '["tcp://127.0.0.1:", "udp://127.0.0.1:", "tcp://localhost:", "udp://localhost:"]'
  fi
}

# brutal_json renders the nested TCP Brutal block for both config writers.
# cwnd_gain 0 means "take the engine default", which is 20 tenths (2.0x); it is
# written out as 20 so the file shows the value that will actually be in force.
brutal_json() {
  local cwnd_gain="${CFG_BRUTAL_CWND_GAIN}"
  if [ "${cwnd_gain}" = "0" ]; then
    cwnd_gain=20
  fi
  printf '{"enabled": %s, "rate": %s, "cwnd_gain": %s, "group_id": %s, "group_from_remote": %s, "bw_exchange": %s, "bw_advertise": %s, "bw_interval": %s}' \
    "${CFG_BRUTAL_ENABLE}" "${CFG_BRUTAL_RATE}" "${cwnd_gain}" "${CFG_BRUTAL_GROUP_ID}" \
    "${CFG_BRUTAL_GROUP_FROM_REMOTE}" "${CFG_BRUTAL_BW_EXCHANGE}" \
    "${CFG_BRUTAL_BW_ADVERTISE}" "${CFG_BRUTAL_BW_INTERVAL}"
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

validate_config() {
  case "${CFG_MODE}" in
    server|client) ;;
    *) die "invalid mode '${CFG_MODE}' (expected server or client)" ;;
  esac

  case "${CFG_PORT}" in
    ''|*[!0-9]*) die "--port must be a number, got '${CFG_PORT}'" ;;
  esac
  if [ "${CFG_PORT}" -lt 1 ] || [ "${CFG_PORT}" -gt 65535 ]; then
    die "--port must be 1-65535, got '${CFG_PORT}'"
  fi

  case "${CFG_LOG_LEVEL}" in debug|info|warn|error) ;;
    *) die "--log-level must be debug|info|warn|error, got '${CFG_LOG_LEVEL}'" ;;
  esac

  case "${CFG_ALPN}" in auto|h3|h2|h1|http/1.1) ;;
    *) die "--alpn must be auto|h3|h2|h1|http/1.1, got '${CFG_ALPN}'" ;;
  esac

  case "${CFG_STREAM_MODE}" in ''|auto|poll|stream) ;;
    *) die "--stream-mode must be auto|poll|stream, got '${CFG_STREAM_MODE}'" ;;
  esac

  local spec name value
  for spec in \
    "max-sessions,${CFG_MAX_SESSIONS}" \
    "max-sessions-per-ip,${CFG_MAX_SESSIONS_PER_IP}" \
    "max-conns,${CFG_MAX_CONNS}" \
    "chunk-size-kb,${CFG_CHUNK_SIZE_KB}" \
    "idle-timeout,${CFG_IDLE_TIMEOUT}" \
    "min-proto-version,${CFG_MIN_PROTO_VERSION}"
  do
    name="${spec%%,*}"
    value="${spec#*,}"
    case "${value}" in
      ''|*[!0-9]*) die "--${name} must be a non-negative integer, got '${value}'" ;;
    esac
  done
  # The binary clamps chunk_size_kb to 16-900; refuse out-of-range values here
  # rather than letting a bad value be rewritten silently at runtime.
  if [ "${CFG_CHUNK_SIZE_KB}" -lt 16 ] || [ "${CFG_CHUNK_SIZE_KB}" -gt 900 ]; then
    die "--chunk-size-kb must be 16-900, got '${CFG_CHUNK_SIZE_KB}'"
  fi

  case "${CFG_SELF_SIGN}" in true|false) ;;
    *) die "--selfsign must be true or false, got '${CFG_SELF_SIGN}'" ;;
  esac
  case "${CFG_ALLOW_PUBLIC_TARGETS}" in true|false) ;;
    *) die "allow-public-targets must be true or false, got '${CFG_ALLOW_PUBLIC_TARGETS}'" ;;
  esac
  case "${CFG_TRUST_PROXY_HEADERS}" in true|false) ;;
    *) die "trust-proxy-headers must be true or false, got '${CFG_TRUST_PROXY_HEADERS}'" ;;
  esac

  # TCP Brutal. Mirrors tunnel.BrutalConfig.Validate so the installer can never
  # write a file the binary refuses to start with.
  local bspec bname bvalue
  for bspec in \
    "brutal-rate,${CFG_BRUTAL_RATE}" \
    "brutal-cwnd-gain,${CFG_BRUTAL_CWND_GAIN}" \
    "brutal-group-id,${CFG_BRUTAL_GROUP_ID}" \
    "brutal-bw-advertise,${CFG_BRUTAL_BW_ADVERTISE}" \
    "brutal-bw-interval,${CFG_BRUTAL_BW_INTERVAL}"
  do
    bname="${bspec%%,*}"
    bvalue="${bspec#*,}"
    case "${bvalue}" in
      ''|*[!0-9]*) die "--${bname} must be a non-negative integer, got '${bvalue}'" ;;
    esac
  done
  case "${CFG_BRUTAL_ENABLE}" in true|false) ;;
    *) die "--brutal-enable must be true or false, got '${CFG_BRUTAL_ENABLE}'" ;;
  esac
  case "${CFG_BRUTAL_GROUP_FROM_REMOTE}" in true|false) ;;
    *) die "--brutal-group-from-remote must be true or false, got '${CFG_BRUTAL_GROUP_FROM_REMOTE}'" ;;
  esac
  case "${CFG_BRUTAL_BW_EXCHANGE}" in true|false) ;;
    *) die "--brutal-bw-exchange must be true or false, got '${CFG_BRUTAL_BW_EXCHANGE}'" ;;
  esac
  # 1e12 bytes/s is the wire ceiling for any rate value. A value with more than
  # 13 digits can never fit under it, and a 13-digit one is safe to compare as
  # an integer, so neither branch can overflow a signed 64-bit test.
  local bceil=1000000000000
  for bspec in "brutal-rate ${CFG_BRUTAL_RATE}" "brutal-bw-advertise ${CFG_BRUTAL_BW_ADVERTISE}"; do
    bname="${bspec%% *}"
    bvalue="${bspec#* }"
    if [ "${#bvalue}" -gt 13 ] || { [ "${#bvalue}" -eq 13 ] && [ "${bvalue}" -gt "${bceil}" ]; }; then
      die "--${bname} exceeds the ${bceil} bytes/s limit, got '${bvalue}'"
    fi
  done
  if [ "${CFG_BRUTAL_CWND_GAIN}" -gt 100 ]; then
    die "--brutal-cwnd-gain must be 0 (the default, 20 tenths) or 1-100 tenths, got '${CFG_BRUTAL_CWND_GAIN}'"
  fi
  if [ "${CFG_BRUTAL_BW_INTERVAL}" -lt 1 ]; then
    die "--brutal-bw-interval must be at least 1 second, got '${CFG_BRUTAL_BW_INTERVAL}'"
  fi
  if [ "${CFG_BRUTAL_BW_EXCHANGE}" = "true" ] && [ "${CFG_BRUTAL_ENABLE}" != "true" ]; then
    die "--brutal-bw-exchange requires --brutal-enable"
  fi
  if [ "${CFG_BRUTAL_BW_ADVERTISE}" -gt 0 ] && [ "${CFG_BRUTAL_BW_EXCHANGE}" != "true" ]; then
    die "--brutal-bw-advertise requires --brutal-bw-exchange"
  fi
  if [ "${CFG_BRUTAL_ENABLE}" = "true" ] && [ "${CFG_BRUTAL_RATE}" -eq 0 ] && [ "${CFG_BRUTAL_BW_EXCHANGE}" != "true" ]; then
    die "--brutal-enable needs --brutal-rate (bytes/s), or --brutal-bw-exchange to let each peer supply one"
  fi
  if [ "${CFG_BRUTAL_GROUP_FROM_REMOTE}" = "true" ] && [ "${CFG_MODE}" != "server" ]; then
    die "--brutal-group-from-remote is a server option; client mode has no peer address to derive a group id from"
  fi
  if [ "${CFG_BRUTAL_ENABLE}" = "true" ] && [ "${CFG_MODE}" = "client" ] && [ "${CFG_ALPN}" = "h3" ]; then
    warn "--brutal-enable has no effect with --alpn h3: HTTP/3 runs over QUIC/UDP and TCP Brutal only caps TCP sockets"
  fi

  if [ "${CFG_MODE}" = "server" ] && [ "${CFG_SELF_SIGN}" = "true" ] && [ -z "${CFG_SELF_SIGN_CN}" ]; then
    die "--selfsign-cn must not be empty when --selfsign is enabled"
  fi
  if [ -n "${CFG_FALLBACK}" ] && ! [[ "${CFG_FALLBACK}" =~ ^https?:// ]]; then
    die "--fallback must be an http(s) URL, got '${CFG_FALLBACK}'"
  fi
  if [ -n "${CFG_HEALTH_PATH}" ] && [[ "${CFG_HEALTH_PATH}" != /* ]]; then
    die "--health-path must start with '/', got '${CFG_HEALTH_PATH}'"
  fi
  if [ "${CFG_MODE}" = "server" ] && [ -n "${CFG_ALLOWED_TARGETS}" ]; then
    validate_allowed_targets "${CFG_ALLOWED_TARGETS}"
  fi

  # Reject the documented example tokens regardless of where they came from
  # (flag, env or interactive). The Go binary refuses the same set at startup.
  psk_trimmed="$(trim_space "${CFG_PSK}")"
  if [ -n "${psk_trimmed}" ] && \
     [[ "${psk_trimmed}" =~ ^(my-secret-token|change-me-before-use|replace-with-a-random-secret)$ ]]; then
    die "the supplied PSK is a published example token; generate a real secret instead"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

write_server_config() {
  local path="$1"
  local listen
  listen="$(derive_listen)"

  cat > "${path}" <<EOF
{
  "_description": "xhttptunnel Split-HTTP / Meek Streaming Server Configuration",
  "_generated_by": "${APP_NAME} install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "server",
  "listen": "$(json_escape "${listen}")",
  "path": "$(json_escape "${CFG_PATH}")",
  "target": "$(json_escape "${CFG_SERVER_TARGET}")",
  "psk": "$(json_escape "${CFG_PSK}")",
  "selfsign": ${CFG_SELF_SIGN},
  "selfsign_cn": "$(json_escape "${CFG_SELF_SIGN_CN}")",
  "cert": "",
  "key": "",
  "fallback": "$(json_escape "${CFG_FALLBACK}")",
  "allowed_targets": $(allowed_targets_json),
  "max_sessions": ${CFG_MAX_SESSIONS},
  "max_sessions_per_ip": ${CFG_MAX_SESSIONS_PER_IP},
  "health_path": "$(json_escape "${CFG_HEALTH_PATH}")",
  "min_proto_version": ${CFG_MIN_PROTO_VERSION},
  "chunk_size_kb": ${CFG_CHUNK_SIZE_KB},
  "trust_proxy_headers": ${CFG_TRUST_PROXY_HEADERS},
  "brutal": $(brutal_json),
  "dump": ${CFG_DUMP},
  "log_level": "$(json_escape "${CFG_LOG_LEVEL}")"
}
EOF
}

write_client_config() {
  local path="$1"
  local sni
  sni="$(client_sni)"

  cat > "${path}" <<EOF
{
  "_description": "xhttptunnel Split-HTTP / Meek Streaming Client Configuration",
  "_generated_by": "${APP_NAME} install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "client",
  "listen": "$(json_escape "${CFG_CLIENT_LISTEN}")",
  "server": "$(json_escape "$(derive_server_url)")",
  "target": "$(json_escape "${CFG_CLIENT_TARGET}")",
  "psk": "$(json_escape "${CFG_PSK}")",
  "sni": "$(json_escape "${sni}")",
  "host": "$(json_escape "${sni}")",
  "alpn": "$(json_escape "${CFG_ALPN}")",
  "stream_mode": "$(json_escape "${CFG_STREAM_MODE}")",
  "fingerprint": "$(json_escape "${CFG_FINGERPRINT}")",
  "chunk_size_kb": ${CFG_CHUNK_SIZE_KB},
  "idle_timeout": ${CFG_IDLE_TIMEOUT},
  "max_conns": ${CFG_MAX_CONNS},
  "brutal": $(brutal_json),
  "dump": ${CFG_DUMP},
  "log_level": "$(json_escape "${CFG_LOG_LEVEL}")"
}
EOF
}

get_config_file() {
  if [ "$1" == "client" ]; then
    echo "${CONFIG_DIR}/config.client.json"
  else
    echo "${CONFIG_DIR}/config.server.json"
  fi
}

write_config_for_mode() {
  local mode="$1" config_file
  config_file="$(get_config_file "${mode}")"
  if [ "${mode}" = "client" ]; then
    write_client_config "${config_file}"
  else
    write_server_config "${config_file}"
  fi
}

# ---------------------------------------------------------------------------
# Summary + confirmation
# ---------------------------------------------------------------------------

mask_psk() {
  if [ -z "${CFG_PSK}" ]; then
    printf '<empty: open mode>'
  elif [ "${#CFG_PSK}" -le 6 ]; then
    printf '%s' "${CFG_PSK}"
  else
    printf '%s... (%d chars)' "${CFG_PSK:0:6}" "${#CFG_PSK}"
  fi
}

print_summary() {
  local path server_url listen sni brutal_note
  path="$(get_config_file "${CFG_MODE}")"
  server_url="$(derive_server_url)"
  listen="$(derive_listen)"
  sni="$(client_sni)"

  echo ""
  echo -e "${BOLD}${GREEN}========================================${PLAIN}"
  echo -e "${BOLD}${GREEN}  Configuration Summary (${CFG_MODE} mode)${PLAIN}"
  echo -e "${BOLD}${GREEN}========================================${PLAIN}"
  printf '  %-24s %s\n' "key" "value"
  printf '  %-24s %s\n' "-----" "-----"
  if [ "${CFG_MODE}" = "client" ]; then
    printf '  %-24s %s\n' "listen" "${CFG_CLIENT_LISTEN}"
    printf '  %-24s %s\n' "port (upstream)" "${CFG_PORT}"
    printf '  %-24s %s\n' "server" "${server_url}"
    printf '  %-24s %s\n' "target" "${CFG_CLIENT_TARGET}"
    printf '  %-24s %s\n' "sni / host" "${sni:-<derived from server URL>}"
    printf '  %-24s %s\n' "alpn" "${CFG_ALPN}"
    printf '  %-24s %s\n' "stream_mode" "${CFG_STREAM_MODE}"
    printf '  %-24s %s\n' "fingerprint" "${CFG_FINGERPRINT:-<empty: CA verification>}"
    printf '  %-24s %s\n' "chunk_size_kb" "${CFG_CHUNK_SIZE_KB}"
    printf '  %-24s %s\n' "idle_timeout" "${CFG_IDLE_TIMEOUT}"
    printf '  %-24s %s\n' "max_conns" "${CFG_MAX_CONNS}"
  else
    printf '  %-24s %s\n' "listen" "${listen}"
    printf '  %-24s %s\n' "port" "${CFG_PORT}"
    printf '  %-24s %s\n' "path" "${CFG_PATH}"
    printf '  %-24s %s\n' "target" "${CFG_SERVER_TARGET}"
    printf '  %-24s %s\n' "selfsign" "${CFG_SELF_SIGN}"
    printf '  %-24s %s\n' "selfsign_cn" "${CFG_SELF_SIGN_CN}"
    printf '  %-24s %s\n' "fallback" "${CFG_FALLBACK}"
    printf '  %-24s %s\n' "allowed_targets" "$(allowed_targets_json)"
    printf '  %-24s %s\n' "max_sessions" "${CFG_MAX_SESSIONS}"
    printf '  %-24s %s\n' "max_sessions_per_ip" "${CFG_MAX_SESSIONS_PER_IP}"
    printf '  %-24s %s\n' "health_path" "${CFG_HEALTH_PATH:-<disabled>}"
    printf '  %-24s %s\n' "min_proto_version" "${CFG_MIN_PROTO_VERSION}"
    printf '  %-24s %s\n' "chunk_size_kb" "${CFG_CHUNK_SIZE_KB}"
    printf '  %-24s %s\n' "trust_proxy_headers" "${CFG_TRUST_PROXY_HEADERS}"
    printf '  %-24s %s\n' "public host" "${CFG_HOST:-<not detected>} (${CFG_HOST_SOURCE})"
  fi
  printf '  %-24s %s\n' "psk" "$(mask_psk)"
  if [ "${CFG_BRUTAL_ENABLE}" = "true" ]; then
    brutal_note="rate ${CFG_BRUTAL_RATE} B/s"
    if [ "${CFG_BRUTAL_BW_EXCHANGE}" = "true" ]; then
      brutal_note="${brutal_note}, exchange every ${CFG_BRUTAL_BW_INTERVAL}s"
      if [ "${CFG_BRUTAL_BW_ADVERTISE}" -gt 0 ]; then
        brutal_note="${brutal_note}, advertise ${CFG_BRUTAL_BW_ADVERTISE} B/s"
      fi
    fi
    if [ "${CFG_BRUTAL_GROUP_FROM_REMOTE}" = "true" ]; then
      brutal_note="${brutal_note}, group per client address"
    elif [ "${CFG_BRUTAL_GROUP_ID}" -gt 0 ]; then
      brutal_note="${brutal_note}, group ${CFG_BRUTAL_GROUP_ID}"
    fi
    printf '  %-24s %s\n' "brutal" "${brutal_note}"
  else
    printf '  %-24s %s\n' "brutal" "off"
  fi
  printf '  %-24s %s\n' "log_level" "${CFG_LOG_LEVEL}"
  printf '  %-24s %s\n' "dump" "${CFG_DUMP}"
  printf '  %-24s %s\n' "-----" "-----"
  printf '  %-24s %s\n' "config file" "${path}"

  # TCP Brutal is a kernel module, so an enabled config can still run uncapped
  # on a host that never loaded it. Warn here rather than fail: the tunnel
  # works either way, and the operator may load the module afterwards.
  if [ "${CFG_BRUTAL_ENABLE}" = "true" ] && ! lsmod 2>/dev/null | grep -q '^tcp_brutal'; then
    echo ""
    warn "--> TCP Brutal is enabled but no tcp_brutal kernel module is loaded, so the tunnel will run uncapped. Load it, or check with: lsmod | grep tcp_brutal"
  fi

  echo ""
  case "${CFG_PSK_SOURCE}" in
    auto) ok "--> PSK auto-generated (256-bit). Full value, keep it safe: ${CYAN}${CFG_PSK}${PLAIN}" ;;
    open) warn "--> PSK is empty: ${CFG_MODE} runs open (no authentication). Do not expose it to the public internet" ;;
    *)    ok "--> PSK source: ${CFG_PSK_SOURCE} (written to the config file, mode 0600)" ;;
  esac
  if [ -z "${CFG_HOST}" ] && [ "${CFG_MODE}" = "server" ]; then
    warn "--> Public host unknown: the share link will contain the YOUR_SERVER_IP placeholder. Pass --host and re-run"
  fi
  if [ "${CFG_MODE}" = "client" ] && [ "${CFG_SELF_SIGN}" = "true" ] && [ -z "${CFG_FINGERPRINT}" ]; then
    echo ""
    warn "--> Note: the server uses a self-signed certificate and fingerprint is empty, so the client will fall back to system CA verification and the handshake will fail."
    echo -e "    Take the fingerprint on the server and put it in the client config fingerprint field:"
    echo -e "    ${CYAN}openssl x509 -in /etc/${APP_NAME}/cert.pem -outform der | sha256sum${PLAIN}"
  fi
}

# prompt_targets asks how far a client may reach through the tunnel and writes
# the answer into CFG_ALLOW_PUBLIC_TARGETS / CFG_ALLOWED_TARGETS. A plain
# yes/no only offered "loopback only" and "anything at all"; option t lets an
# operator type an exact allowed_targets list instead.
prompt_targets() {
  local answer
  printf "  ${PLAIN}(n = loopback only: 127.0.0.1 / localhost, default and recommended)\n" >&2
  printf "  ${PLAIN}(y = allow every target, unrestricted)\n" >&2
  printf "  ${PLAIN}(${CYAN}t${PLAIN} = type allowed_targets entries, comma separated)\n" >&2
  prompt_input "Target policy" "n"
  answer="${PROMPT_REPLY}"
  case "${answer}" in
    y|yes|all)
      CFG_ALLOW_PUBLIC_TARGETS="true"
      CFG_ALLOWED_TARGETS=""
      ;;
    t|targets|custom)
      prompt_input "allowed_targets (e.g. tcp://192.168.1.10: , udp://:53)" ""
      CFG_ALLOWED_TARGETS="${PROMPT_REPLY}"
      if [ -z "$(trim_space "${CFG_ALLOWED_TARGETS}")" ]; then
        # An empty custom list would otherwise fall back to unrestricted, which
        # is the opposite of what "t" asks for. Keep the loopback preset.
        CFG_ALLOW_PUBLIC_TARGETS="false"
        CFG_ALLOWED_TARGETS=""
        warn "--> No allowed_targets entered; falling back to the loopback-only policy"
      else
        CFG_ALLOW_PUBLIC_TARGETS="true"
      fi
      ;;
    *)
      CFG_ALLOW_PUBLIC_TARGETS="false"
      CFG_ALLOWED_TARGETS=""
      ;;
  esac
}

# collect_config resolves the wizard questions, but only when a terminal is
# attached and the value was not already supplied as a flag or the environment.
collect_config() {
  resolve_host
  if [ "${INTERACTIVE}" -eq 1 ]; then
    echo ""
    echo -e "${BOLD}--- Deployment Wizard (${CFG_MODE} mode) ---${PLAIN}"
    if ! has_flag port; then
      prompt_input "Listen port" "${CFG_PORT}"
      CFG_PORT="${PROMPT_REPLY}"
    fi
    if [ "${CFG_MODE}" = "server" ]; then
      prompt_input "Self-signed cert disguise domain (selfsign_cn)" "${CFG_SELF_SIGN_CN}"
      CFG_SELF_SIGN_CN="${PROMPT_REPLY}"
      prompt_input "Decoy fallback URL (fallback)" "${CFG_FALLBACK}"
      CFG_FALLBACK="${PROMPT_REPLY}"
      if ! has_flag public_targets && ! has_flag allowed_targets; then
        prompt_targets
      fi
    fi
  fi
  resolve_psk
  print_summary
}

# confirm_write lets an interactive user keep an existing configuration instead
# of overwriting it. Returns 1 when the existing file should be preserved.
confirm_write() {
  if [ "${ASSUME_YES}" = "true" ] || [ "${INTERACTIVE}" -ne 1 ]; then
    return 0
  fi
  local path answer
  path="$(get_config_file "${CFG_MODE}")"
  if [ -f "${path}" ] && [ -s "${path}" ] && [ "${FORCE_OVERWRITE}" != "true" ]; then
    warn "--> Existing configuration found: ${path}"
    prompt_yesno "Overwrite the existing configuration?" "n"
    answer="${PROMPT_REPLY}"
    if [ "${answer}" != "true" ]; then
      warn "--> Keeping the existing configuration; not written"
      return 1
    fi
    FORCE_OVERWRITE="true"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
  cat <<EOF
${APP_NAME} installer

Usage:
  sudo $0 [install [server|client]]   Install binary, generate config, register service
  sudo $0 reconfig [server|client]   Re-run the configuration wizard only (no binary/systemd change)
  sudo $0 upgrade|update              Upgrade the binary and restart the service
  sudo $0 uninstall|remove            Stop, disable and remove the service and binary
  sudo $0 start|stop|restart|status   Manage the systemd service
  sudo $0 logs                        Tail the service journal
  sudo $0 uri|qr                      Print the Stun share URI and QR code

Environment:
  XHTTPTUNNEL_VERSION                 Pin the release tag to install (default: latest)
  XHTTPTUNNEL_CONFIG_DIR              Config directory (default: /etc/${APP_NAME})
  XHTTPTUNNEL_INSTALL_DIR             Binary directory (default: /usr/local/bin)
  XHTTPTUNNEL_SYSTEMD_DIR             Unit directory (default: /etc/systemd/system)
  XHTTPTUNNEL_HOST                    Public host (skip the auto-detection prompt)
  XHTTPTUNNEL_PORT                    Listen port (skip the port prompt)
  XHTTPTUNNEL_SELF_SIGN_CN            Common name for the self-signed certificate
  XHTTPTUNNEL_FALLBACK                Fallback URL for unauthorized requests
  XHTTPTUNNEL_PSK                     PSK token (skip the PSK prompt)
  XHTTPTUNNEL_ALLOW_PUBLIC_TARGETS    1/true = allow non-loopback targets
  XHTTPTUNNEL_ALLOWED_TARGETS         Exact allowed_targets list, comma separated
  GEN_URI_HOST / GEN_URI_PIN          Share-URI host override / fixed 6-digit PIN

Configuration flags (a value given here is used verbatim and never prompted):
  --host <ip|domain>        Public host for the share URI and the client URL
  --no-auto-ip              Do not probe for the public IP
  --port <n>                Listen port (default 8443, asked by the wizard)
  --path <path>             Tunnel path (default /stream)
  --listen <addr>           Server bind address (default :<port>)
  --target <tcp://h:p>      Server default target (default tcp://127.0.0.1:22)
  --allow-public-targets    Allow clients to request non-loopback targets
  --no-public-targets       Restrict targets to 127.0.0.1 / localhost (default).
                            allowed_targets entries are host:port, :port,
                            host:, [host] or *, prefixed tcp:// or udp:// to
                            allow only that protocol (udp://:53 = any host's
                            UDP DNS). Empty = unrestricted; edit the JSON to
                            add more entries.
  --allowed-targets <list>  Exact allowed_targets list (comma separated), e.g.
                            --allowed-targets "tcp://192.168.1.10:, udp://:53".
                            Overrides the loopback preset and both
                            --allow-public-targets / --no-public-targets.
  --selfsign | --no-selfsign
  --selfsign-cn <cn>        Common name for the self-signed certificate
  --fallback <url>          Fallback URL for unauthorized requests
  --psk <value>             Explicit PSK; --psk "" selects open mode
  --psk-auto | --psk-manual PSK mode (server defaults to auto, client to manual)
  --sni <domain>            Client TLS SNI and HTTP Host (default: selfsign_cn, else derived)
  --fingerprint <hex>       Client certificate pin (SHA-256 of the DER certificate)
  --max-sessions <n>        Server max concurrent sessions (default 2000)
  --max-sessions-per-ip <n> Server per-IP session cap (default 50, 0 = unlimited)
  --health-path <path>      Unauthenticated stats endpoint, e.g. /healthz (default off)
  --min-proto-version <n>   Reject clients below this protocol version (default 0)
  --chunk-size-kb <n>       Poll body cap, 16-900 (default 256, must match both ends)
  --trust-proxy-headers     Trust CF-Connecting-IP / X-Forwarded-For (default off)
  --brutal-enable [b]       Cap TCP tunnel socket send rate with TCP Brutal, a
                            Linux kernel module (default off). A missing module
                            never breaks a tunnel: it runs uncapped instead
  --brutal-rate <n>         brutal send ceiling in bytes/s. Required when
                            --brutal-enable is on and --brutal-bw-exchange is not
                            (default 0, maximum 1000000000000)
  --brutal-cwnd-gain <n>    brutal cwnd_gain in tenths, so 20 = 2.0x (default
                            0 = the engine default of 20, maximum 100)
  --brutal-group-id <n>     brutal connection group id; members share the rate
                            as an aggregate ceiling (default 0 = per-connection)
  --brutal-group-from-remote [b]
                            Server only: derive the group from the client
                            address instead of --brutal-group-id. A static group
                            id pools every client into one aggregate ceiling
  --brutal-bw-exchange [b]  Exchange ingest rates over the _BrutalBwExchange
                            protocol (default off; requires --brutal-enable)
  --brutal-bw-advertise <n> bytes/s this side can ingest, offered to the peer,
                            which applies it as its own send rate (default 0 =
                            don't offer anything; requires --brutal-bw-exchange)
  --brutal-bw-interval <s>  Seconds between bandwidth exchange attempts
                            (default 60, minimum 1)
  --client-listen <addr>    Client local listen (default tcp://127.0.0.1:1080)
  --client-target <h:p>     Client forward target (default 127.0.0.1:22)
  --server-url <url>        Client upstream URL (default derived from host/port/path)
  --max-conns <n>           Client max concurrent connections (installer default 512; 0 = engine default 2000)
  --idle-timeout <s>        Client idle timeout in seconds (default 900)
  --alpn <auto|h3|h2|h1>    Client transport selection (default auto)
  --stream-mode <mode>      Client downlink: auto|poll|stream (default auto)
  --log-level <level>       debug|info|warn|error (default info)
  --dump                    Hex-dump tunnelled traffic (default off)
  --force                   Overwrite an existing configuration
  --yes                     Do not ask for confirmation
  --non-interactive         Never prompt; use flags, env vars and defaults only
  --help                    This help

Resolution order: command-line flag > environment variable > interactive prompt > default.
When stdin is not a terminal the wizard is skipped automatically.
EOF
}

parse_args() {
  local positional=()
  local mode_hint
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) usage; exit 0 ;;

      --host) [ "$#" -ge 2 ] || die "--host needs a value"; CFG_HOST="$2"; CFG_HOST_SOURCE="flag"; mark_flag host; shift 2 ;;
      --no-auto-ip) CFG_HOST_AUTO="off"; shift ;;
      --port) [ "$#" -ge 2 ] || die "--port needs a value"; CFG_PORT="$2"; mark_flag port; shift 2 ;;
      --path) [ "$#" -ge 2 ] || die "--path needs a value"; CFG_PATH="$2"; shift 2 ;;
      --listen) [ "$#" -ge 2 ] || die "--listen needs a value"; CFG_LISTEN="$2"; shift 2 ;;
      --target) [ "$#" -ge 2 ] || die "--target needs a value"; CFG_SERVER_TARGET="$2"; shift 2 ;;
      --allow-public-targets) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_ALLOW_PUBLIC_TARGETS="$(to_bool "$2")"; shift 2; else CFG_ALLOW_PUBLIC_TARGETS="true"; shift; fi; mark_flag public_targets ;;
      --no-public-targets) CFG_ALLOW_PUBLIC_TARGETS="false"; mark_flag public_targets; shift ;;
      --allowed-targets) [ "$#" -ge 2 ] || die "--allowed-targets needs a value"; CFG_ALLOWED_TARGETS="$2"; CFG_ALLOW_PUBLIC_TARGETS="true"; mark_flag allowed_targets; shift 2 ;;
      --selfsign) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_SELF_SIGN="$(to_bool "$2")"; shift 2; else CFG_SELF_SIGN="true"; shift; fi ;;
      --no-selfsign) CFG_SELF_SIGN="false"; shift ;;
      --selfsign-cn) [ "$#" -ge 2 ] || die "--selfsign-cn needs a value"; CFG_SELF_SIGN_CN="$2"; mark_flag selfsign_cn; shift 2 ;;
      --fallback) [ "$#" -ge 2 ] || die "--fallback needs a value"; CFG_FALLBACK="$2"; mark_flag fallback; shift 2 ;;
      --psk) [ "$#" -ge 2 ] || die "--psk needs a value"; CFG_PSK="$2"; CFG_PSK_GIVEN="true"; shift 2 ;;
      --psk-auto) CFG_PSK_MODE="auto"; shift ;;
      --psk-manual) CFG_PSK_MODE="manual"; shift ;;
      --sni) [ "$#" -ge 2 ] || die "--sni needs a value"; CFG_SNI="$2"; shift 2 ;;
      --fingerprint) [ "$#" -ge 2 ] || die "--fingerprint needs a value"; CFG_FINGERPRINT="$2"; shift 2 ;;
      --max-sessions) [ "$#" -ge 2 ] || die "--max-sessions needs a value"; CFG_MAX_SESSIONS="$2"; shift 2 ;;
      --max-sessions-per-ip) [ "$#" -ge 2 ] || die "--max-sessions-per-ip needs a value"; CFG_MAX_SESSIONS_PER_IP="$2"; shift 2 ;;
      --health-path) [ "$#" -ge 2 ] || die "--health-path needs a value"; CFG_HEALTH_PATH="$2"; shift 2 ;;
      --min-proto-version) [ "$#" -ge 2 ] || die "--min-proto-version needs a value"; CFG_MIN_PROTO_VERSION="$2"; shift 2 ;;
      --chunk-size-kb) [ "$#" -ge 2 ] || die "--chunk-size-kb needs a value"; CFG_CHUNK_SIZE_KB="$2"; shift 2 ;;
      --trust-proxy-headers) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_TRUST_PROXY_HEADERS="$(to_bool "$2")"; shift 2; else CFG_TRUST_PROXY_HEADERS="true"; shift; fi ;;
      --no-trust-proxy-headers) CFG_TRUST_PROXY_HEADERS="false"; shift ;;
      --brutal-enable) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_BRUTAL_ENABLE="$(to_bool "$2")"; shift 2; else CFG_BRUTAL_ENABLE="true"; shift; fi ;;
      --brutal-rate) [ "$#" -ge 2 ] || die "--brutal-rate needs a value"; CFG_BRUTAL_RATE="$2"; shift 2 ;;
      --brutal-cwnd-gain) [ "$#" -ge 2 ] || die "--brutal-cwnd-gain needs a value"; CFG_BRUTAL_CWND_GAIN="$2"; shift 2 ;;
      --brutal-group-id) [ "$#" -ge 2 ] || die "--brutal-group-id needs a value"; CFG_BRUTAL_GROUP_ID="$2"; shift 2 ;;
      --brutal-group-from-remote) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_BRUTAL_GROUP_FROM_REMOTE="$(to_bool "$2")"; shift 2; else CFG_BRUTAL_GROUP_FROM_REMOTE="true"; shift; fi ;;
      --brutal-bw-exchange) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_BRUTAL_BW_EXCHANGE="$(to_bool "$2")"; shift 2; else CFG_BRUTAL_BW_EXCHANGE="true"; shift; fi ;;
      --brutal-bw-advertise) [ "$#" -ge 2 ] || die "--brutal-bw-advertise needs a value"; CFG_BRUTAL_BW_ADVERTISE="$2"; shift 2 ;;
      --brutal-bw-interval) [ "$#" -ge 2 ] || die "--brutal-bw-interval needs a value"; CFG_BRUTAL_BW_INTERVAL="$2"; shift 2 ;;
      --client-listen) [ "$#" -ge 2 ] || die "--client-listen needs a value"; CFG_CLIENT_LISTEN="$2"; shift 2 ;;
      --client-target) [ "$#" -ge 2 ] || die "--client-target needs a value"; CFG_CLIENT_TARGET="$2"; shift 2 ;;
      --server-url) [ "$#" -ge 2 ] || die "--server-url needs a value"; CFG_SERVER_URL="$2"; shift 2 ;;
      --max-conns) [ "$#" -ge 2 ] || die "--max-conns needs a value"; CFG_MAX_CONNS="$2"; shift 2 ;;
      --idle-timeout) [ "$#" -ge 2 ] || die "--idle-timeout needs a value"; CFG_IDLE_TIMEOUT="$2"; shift 2 ;;
      --alpn) [ "$#" -ge 2 ] || die "--alpn needs a value"; CFG_ALPN="$2"; shift 2 ;;
      --stream-mode) [ "$#" -ge 2 ] || die "--stream-mode needs a value"; CFG_STREAM_MODE="$2"; shift 2 ;;
      --log-level) [ "$#" -ge 2 ] || die "--log-level needs a value"; CFG_LOG_LEVEL="$2"; shift 2 ;;
      --dump) if [ "$#" -ge 2 ] && bool_value "$2"; then CFG_DUMP="$(to_bool "$2")"; shift 2; else CFG_DUMP="true"; shift; fi ;;
      --no-dump) CFG_DUMP="false"; shift ;;
      --force) FORCE_OVERWRITE="true"; shift ;;
      --yes|-y) ASSUME_YES="true"; shift ;;
      --non-interactive|--no-interactive) INTERACTIVE=0; shift ;;

      -*) die "unknown option: $1 (see --help)" ;;

      *) positional+=("$1"); shift ;;
    esac
  done

  CFG_ACTION="${positional[0]:-install}"
  mode_hint="${positional[1]:-}"
  case "${mode_hint}" in server|client) CFG_MODE="${mode_hint}" ;; esac

  # Legacy aliases: `install.sh server` == `install.sh install server`.
  case "${CFG_ACTION}" in
    server|install-server) CFG_ACTION="install"; CFG_MODE="server" ;;
    client|install-client) CFG_ACTION="install"; CFG_MODE="client" ;;
  esac

  # Anything past the action and an optional mode hint is a typo. Boolean flags
  # take no value, so a value typed after one lands here as a positional -- die
  # on it instead of silently installing with the default.
  if [ "${#positional[@]}" -gt 2 ]; then
    die "unexpected argument: ${positional[2]} (see --help)"
  fi
  case "${CFG_ACTION}" in
    install|reconfig|upgrade|update|uninstall|remove|start|stop|restart|status|logs|log|uri|qr) ;;
    *) die "unknown action: ${CFG_ACTION} (see --help)" ;;
  esac

  # A server may invent its own secret; a client may not.
  if [ "${CFG_MODE}" = "client" ] && [ "${CFG_PSK_GIVEN}" != "true" ] && [ "${CFG_PSK_MODE}" = "auto" ]; then
    CFG_PSK_MODE="manual"
  fi

  # Environment overrides, applied after flags so an explicit flag wins.
  if [ -n "${XHTTPTUNNEL_HOST:-}" ] && ! has_flag host; then
    CFG_HOST="${XHTTPTUNNEL_HOST}"
    CFG_HOST_SOURCE="env"
  fi
  if [ -n "${XHTTPTUNNEL_PORT:-}" ] && ! has_flag port; then
    CFG_PORT="${XHTTPTUNNEL_PORT}"
  fi
  if [ -n "${XHTTPTUNNEL_SELF_SIGN_CN:-}" ] && ! has_flag selfsign_cn; then
    CFG_SELF_SIGN_CN="${XHTTPTUNNEL_SELF_SIGN_CN}"
  fi
  if [ -n "${XHTTPTUNNEL_FALLBACK:-}" ] && ! has_flag fallback; then
    CFG_FALLBACK="${XHTTPTUNNEL_FALLBACK}"
  fi
  if [ -n "${XHTTPTUNNEL_PSK:-}" ] && [ "${CFG_PSK_GIVEN}" != "true" ]; then
    CFG_PSK="${XHTTPTUNNEL_PSK}"
    CFG_PSK_GIVEN="true"
    CFG_PSK_SOURCE="env"
  fi
  case "${XHTTPTUNNEL_ALLOW_PUBLIC_TARGETS:-}" in
    1|true|TRUE|yes|YES|on|ON) CFG_ALLOW_PUBLIC_TARGETS="true"; mark_flag public_targets ;;
  esac
  if [ -n "${XHTTPTUNNEL_ALLOWED_TARGETS:-}" ]; then
    CFG_ALLOWED_TARGETS="${XHTTPTUNNEL_ALLOWED_TARGETS}"
    CFG_ALLOW_PUBLIC_TARGETS="true"
    mark_flag allowed_targets
  fi

  if [ "${INTERACTIVE}" -eq 1 ] && ! is_tty; then
    INTERACTIVE=0
    warn "--> stdin is not a terminal; switched to non-interactive mode (pass --host/--psk/... instead)"
  fi
}

# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------

get_arch() {
  local arch
  arch=$(uname -m)
  case "${arch}" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    armv7l)  echo "arm" ;;
    i386|i686) echo "386" ;;
    *) die "Unsupported CPU architecture: ${arch}" ;;
  esac
}

get_release_download_url() {
  local goarch="$1" release_path
  if [ "${RELEASE_VERSION}" = "latest" ]; then
    release_path="latest/download"
  else
    case "${RELEASE_VERSION}" in */*) die "Invalid release tag: ${RELEASE_VERSION}" ;; esac
    release_path="download/${RELEASE_VERSION}"
  fi
  echo "https://github.com/${GITHUB_REPO}/releases/${release_path}/${APP_NAME}_linux_${goarch}"
}

install_binary() {
  local goarch
  goarch=$(get_arch)
  mkdir -p "${INSTALL_DIR}"

  if [ -f "./bin/${APP_NAME}_linux_${goarch}" ]; then
    info "--> Using local prebuilt binary (linux/${goarch})..."
    cp -f "./bin/${APP_NAME}_linux_${goarch}" "${INSTALL_DIR}/${APP_NAME}"
  elif [ -f "./${APP_NAME}" ]; then
    info "--> Using local binary..."
    cp -f "./${APP_NAME}" "${INSTALL_DIR}/${APP_NAME}"
  elif command -v go >/dev/null 2>&1 && [ -f "./main.go" ]; then
    info "--> Building from source with Go..."
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "${INSTALL_DIR}/${APP_NAME}" .
  else
    info "--> Downloading ${RELEASE_VERSION} release binary (${goarch})..."
    local download_url tmp_bin
    download_url=$(get_release_download_url "${goarch}")
    tmp_bin=$(mktemp "/tmp/${APP_NAME}.XXXXXX" 2>/dev/null || echo "/tmp/${APP_NAME}.$$")

    # Check if target path is accidentally a directory
    if [ -d "${INSTALL_DIR}/${APP_NAME}" ]; then
      die "${INSTALL_DIR}/${APP_NAME} is a directory! Please remove it first"
    fi

    # Direct download from GitHub Releases
    if ! curl -fL --retry 3 --connect-timeout 15 -o "${tmp_bin}" "${download_url}" || [ ! -s "${tmp_bin}" ]; then
      rm -f "${tmp_bin}"
      die "Failed to download release binary from GitHub!
Download URL: ${download_url}
Please check network connectivity or disk space."
    fi

    chmod +x "${tmp_bin}"
    # Atomically replace target binary using mv (handles a running process / ETXTBSY)
    mv -f "${tmp_bin}" "${INSTALL_DIR}/${APP_NAME}"
  fi

  chmod +x "${INSTALL_DIR}/${APP_NAME}"
  ok "--> Binary installed to ${INSTALL_DIR}/${APP_NAME}"
}

# has_placeholder_psk reports whether a config file still carries one of the
# published example tokens, which the binary refuses to run with.
has_placeholder_psk() {
  grep -Eq '"psk"[[:space:]]*:[[:space:]]*"(my-secret-token|change-me-before-use|replace-with-a-random-secret)"' "$1"
}

install_config() {
  local mode="$1" config_file
  config_file="$(get_config_file "${mode}")"
  # install -d sets the mode in one step; fall back to plain mkdir on shells
  # that cannot change directory permissions (e.g. Git Bash without chmod).
  if ! install -d -m 0750 "${CONFIG_DIR}" 2>/dev/null; then
    mkdir -p "${CONFIG_DIR}"
  fi

  if [ ! -f "${config_file}" ] || [ ! -s "${config_file}" ]; then
    write_config_for_mode "${mode}"
    ok "--> Created ${mode} configuration at ${config_file}"
  elif [ "${FORCE_OVERWRITE}" = "true" ]; then
    write_config_for_mode "${mode}"
    ok "--> Overwrote existing ${mode} configuration at ${config_file}"
  else
    warn "--> Existing configuration preserved at ${config_file} (use --force to overwrite)"
    # A preserved file still carrying an example token would make the binary
    # refuse to start, so surface it here instead of at boot time.
    if has_placeholder_psk "${config_file}"; then
      die "existing ${mode} configuration at ${config_file} uses a published example PSK; rotate it (or re-run with --force)"
    fi
  fi

  chown root:root "${config_file}" 2>/dev/null || true
  chmod 0600 "${config_file}"
}

install_systemd() {
  local mode="$1" config_file desc
  config_file="$(get_config_file "${mode}")"
  desc="Split-HTTP / Meek Tunnel Server"
  [ "${mode}" = "client" ] && desc="Split-HTTP / Meek Tunnel Client"

  install -d "${SYSTEMD_DIR}"
  cat > "${SERVICE_FILE}" <<EOF
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
  chmod 0644 "${SERVICE_FILE}"

  systemctl daemon-reload
  systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
  ok "--> Systemd service registered: ${APP_NAME}.service (${mode} mode)"
}

# gen_uri_extra_args builds the extra flags for the binary's gen-uri command.
# The resolved public host is passed through, removing the previous need to set
# GEN_URI_HOST by hand (the server config only ever knew its own port).
gen_uri_extra_args() {
  local args="" host
  if [ -n "${GEN_URI_PIN:-}" ]; then
    args="${args} -pin ${GEN_URI_PIN}"
  fi
  host="${GEN_URI_HOST:-${CFG_HOST:-}}"
  if [ -n "${host}" ]; then
    args="${args} -host ${host}"
  fi
  printf '%s' "${args}"
}

service_registered() {
  systemctl list-unit-files "${APP_NAME}.service" 2>/dev/null | grep -q "${APP_NAME}.service"
}

do_install() {
  local mode="$1" config_file
  CFG_MODE="${mode}"
  config_file="$(get_config_file "${mode}")"

  check_root
  echo -e "${GREEN}========================================${PLAIN}"
  echo -e "${GREEN}  Installing ${APP_NAME} (${mode} mode)...${PLAIN}"
  echo -e "${GREEN}========================================${PLAIN}"

  install_binary
  collect_config
  validate_config
  confirm_write || true
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
      warn "    Share PIN (via GEN_URI_PIN): ${GEN_URI_PIN}"
    else
      warn "    A random PIN was printed above -- note it to import the URI."
    fi
  fi
}

do_reconfig() {
  local mode="$1" config_file
  CFG_MODE="${mode}"
  config_file="$(get_config_file "${mode}")"

  check_root
  echo -e "${YELLOW}========================================${PLAIN}"
  echo -e "${YELLOW}  Reconfiguring ${APP_NAME} (${mode} mode)...${PLAIN}"
  echo -e "${YELLOW}========================================${PLAIN}"

  FORCE_OVERWRITE="true"
  collect_config
  validate_config
  confirm_write || true
  install_config "${mode}"

  if service_registered; then
    systemctl restart "${APP_NAME}" || true
    ok "--> Service restarted to apply the new configuration"
  else
    warn "--> No ${APP_NAME} service registered; run it manually with ${APP_NAME} -c ${config_file}"
  fi
  echo -e "Configuration: ${CYAN}${config_file}${PLAIN}"
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

main() {
  parse_args "$@"

  case "${CFG_ACTION}" in
    install) do_install "${CFG_MODE}" ;;
    reconfig) do_reconfig "${CFG_MODE}" ;;
    upgrade|update) do_upgrade ;;
    uninstall|remove) do_uninstall ;;
    start) do_start ;;
    stop) do_stop ;;
    restart) do_restart ;;
    status) do_status ;;
    logs|log) do_logs ;;
    uri|qr) do_uri ;;
    *)
      echo "Usage: $0 {install [server|client]|reconfig [server|client]|upgrade|uninstall|start|stop|restart|status|logs|uri}"
      exit 1
      ;;
  esac
}

# The dispatch is wrapped so the script can be sourced for testing the config
# pipeline (collect_config / validate_config / write_*_config) in isolation.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
