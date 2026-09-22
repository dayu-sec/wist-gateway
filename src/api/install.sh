#!/usr/bin/env sh
# wist-agentd 安装脚本（由 wist-gateway 渲染签名后下发，本文件已被签名校验过）。
#
# 顺序：装包并校验摘要 → 装二进制 → 写初始配置 → 注册常驻服务（交给 launchd / systemd）。
# 幂等：重跑等价于升级（覆盖二进制 + 重建服务进程）；任何一步失败都会明确说明停在哪。
set -eu

# 自我提权时用参数回传一次性 token：sudo 默认会清掉父进程的环境变量，参数不会。
# 页面生成的安装指令不带参数（`sh <脚本>`），只有系统级自我提权那一次会带。
while [ "$#" -gt 0 ]; do
  case "$1" in
    --enrollment-token)
      if [ "$#" -lt 2 ]; then
        printf '%s\n' "--enrollment-token 缺少取值" >&2
        exit 1
      fi
      WIST_ENROLLMENT_TOKEN="$2"
      shift 2
      ;;
    *)
      printf '未知参数 %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

ARCH="{{ARCH}}"
AGENT_PACKAGE_SHA256="{{AGENT_PACKAGE_SHA256}}"
# 网关生成的安装指令导出 WARP_INSIGHT_ENROLLMENT_TOKEN（旧命名），脚本读 WIST_ENROLLMENT_TOKEN。
# 两个名字都接受：否则照着页面复制粘贴就会静默丢掉 token。
WIST_ENROLLMENT_TOKEN="${WIST_ENROLLMENT_TOKEN:-${WARP_INSIGHT_ENROLLMENT_TOKEN:-}}"

OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"
case "$OS_NAME" in
  Darwin) SERVICE_MANAGER="launchd" ;;
  Linux) SERVICE_MANAGER="systemd" ;;
  *) SERVICE_MANAGER="服务管理器" ;;
esac

# 作用域默认**系统级**：开机自起（不依赖登录）、能读 /var/log 等受限路径，配置落
# /etc/wist-agentd，数据与日志分别落 /var/lib|/var/log/wist-agentd。
# 要装用户级（免 sudo、登录即起、全部落 ${HOME}）就设 WIST_AGENTD_SCOPE=user。
#
# 系统级配置目录只能是 /etc/wist-agentd：agentd 只把该目录（及其子目录）认作系统级
# （`is_system_config_dir`），并据此把数据放 /var/lib/wist-agentd、日志放
# /var/log/wist-agentd。落到别处就不再是系统级布局，run/state/spool 与日志会退回配置目录下。
SCOPE="${WIST_AGENTD_SCOPE:-system}"
case "$SCOPE" in
  system)
    SERVICE_SCOPE_ARG="--system"
    SERVICE_SCOPE_NOTE="system（开机自起，以 root 运行）"
    ;;
  user)
    SERVICE_SCOPE_ARG="--user"
    SERVICE_SCOPE_NOTE="user（登录即起，以当前用户运行）"
    ;;
  *)
    printf 'WIST_AGENTD_SCOPE 只能是 system 或 user，收到 %s\n' "$SCOPE" >&2
    exit 2
    ;;
esac
# 系统级由脚本自己提权，而不是要求使用者手工加 sudo：手工加 sudo 会清掉 token 所在的
# 环境变量，token 静默丢失、脚本退到交互提示。重新执行自己时把 token 作为参数带过去。
if [ "$SCOPE" = "system" ] && [ "$(id -u)" != "0" ]; then
  if [ ! -f "$0" ] || { [ ! -t 0 ] && [ ! -r /dev/tty ]; }; then
    printf '%s\n' "系统级安装需要 root：请用 sudo 重跑本脚本，或设 WIST_AGENTD_SCOPE=user 装用户级。" >&2
    exit 2
  fi
  exec sudo -p '系统级安装需要管理员权限: ' sh "$0" --enrollment-token "$WIST_ENROLLMENT_TOKEN" "$@"
fi
# 二进制放标准 bin 目录，与配置目录解耦；配置目录只放 config + tasks。
# （系统级下 state/run/spool 落 /var/lib/wist-agentd、日志落 /var/log/wist-agentd。）
if [ "$SCOPE" = "system" ]; then
  WIST_AGENTD_HOME="${WIST_AGENTD_HOME:-/etc/wist-agentd}"
  BIN_DIR="${WIST_AGENTD_BIN_DIR:-/usr/local/bin}"
else
  WIST_AGENTD_HOME="${WIST_AGENTD_HOME:-$HOME/.wist-agentd}"
  BIN_DIR="${WIST_AGENTD_BIN_DIR:-$HOME/bin}"
fi
CONFIG_DIR="$WIST_AGENTD_HOME"

# 输出约定：`==> ` 是脚本自己推进的步骤，缩进的是外部工具（wist-agentd / curl）的输出，
# 这样一行是哪来的、停在哪一步都一眼可辨。只在交互终端上色，重定向到文件或 CM 时退化为纯文本。
if [ -t 1 ]; then
  BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"
  GREEN="$(printf '\033[32m')"; RED="$(printf '\033[31m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; DIM=""; GREEN=""; RED=""; RESET=""
fi
step() { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RESET"; }
note() { printf '    %s\n' "$1"; }
bad() { printf '%s%s%s\n' "$RED" "$1" "$RESET" >&2; }
# 把 $HOME 前缀缩成 `~`：这几处路径只用于显示，不参与任何判断。
short() {
  case "$1" in
    "$HOME"/*) printf '~%s' "${1#"$HOME"}" ;;
    *) printf '%s' "$1" ;;
  esac
}
# 外部工具的输出统一缩进一级，并把其中的 $HOME 也缩成 `~`（同样只为显示好看）。
indent_tool_output() {
  awk -v home="$HOME" '{
    i = index($0, home)
    if (length(home) > 1 && i > 0) {
      $0 = substr($0, 1, i - 1) "~" substr($0, i + length(home))
    }
    print "    " $0
  }'
}
show_tool_output() {
  printf '%s' "$DIM"
  indent_tool_output <"$1"
  printf '%s' "$RESET"
}

printf '%swist-agentd 安装程序%s\n' "$BOLD" "$RESET"
printf '  主机    %s %s\n' "$OS_NAME" "$HOST_ARCH"
printf '  作用域  %s\n' "$SERVICE_SCOPE_NOTE"
printf '  二进制  %s\n' "$(short "$BIN_DIR/wist-agentd")"
printf '  配置    %s\n' "$(short "$CONFIG_DIR/agentd.toml")"

if [ -z "${WIST_ENROLLMENT_TOKEN:-}" ]; then
  if [ -r /dev/tty ]; then
    printf "Enrollment token: " >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    IFS= read -r WIST_ENROLLMENT_TOKEN </dev/tty
    stty echo </dev/tty 2>/dev/null || true
    printf "\n" >/dev/tty
  fi
fi
if [ -z "${WIST_ENROLLMENT_TOKEN:-}" ]; then
  bad "missing WIST_ENROLLMENT_TOKEN"
  echo "  请用网关页面生成的安装命令（它会带上 token），或让本脚本交互读取。" >&2
  exit 1
fi

umask 077
mkdir -p "$BIN_DIR" "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

# 网关渲染时把它的信任锚（CA PEM）嵌进本脚本：下面的两次下载都用它校验网关 TLS。
# 本脚本自身已被签名校验过，所以内嵌的信任锚是可信的。
CA_CERT="$(mktemp)"
cat >"$CA_CERT" <<'EOF'
{{TRUST_BUNDLE}}
EOF
chmod 0600 "$CA_CERT"

PACKAGE_FILE="$(mktemp "${TMPDIR:-/tmp}/wist-package.XXXXXX")"
EXTRACT_DIR=""
TOOL_OUT=""
cleanup() {
  rm -f "$CA_CERT" "$PACKAGE_FILE"
  if [ -n "$EXTRACT_DIR" ]; then rm -rf "$EXTRACT_DIR"; fi
  if [ -n "$TOOL_OUT" ]; then rm -f "$TOOL_OUT"; fi
}
trap cleanup EXIT INT TERM

step "[1/4] 下载安装包并校验摘要"
# 摘要校验针对**下载到的制品本身**（tarball 或裸二进制），在解包之前做。
if ! curl -fsSL --cacert "$CA_CERT" -H "authorization: Bearer $WIST_ENROLLMENT_TOKEN" "{{AGENT_PACKAGE_URL}}" -o "$PACKAGE_FILE"; then
  bad "下载安装包失败：见上方 curl 报错（网络不可达 / 证书不受信任 / token 失效）。"
  exit 1
fi
if [ -n "$AGENT_PACKAGE_SHA256" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(shasum -a 256 "$PACKAGE_FILE" | awk '{print $1}')"
  else
    bad "missing sha256sum or shasum for package verification"
    exit 1
  fi
  if [ "$ACTUAL_SHA256" != "$AGENT_PACKAGE_SHA256" ]; then
    bad "agent package sha256 mismatch: expected $AGENT_PACKAGE_SHA256 got $ACTUAL_SHA256"
    echo "  下发内容与网关记录的摘要不一致，已中止（本地已有安装未被改动）。" >&2
    exit 1
  fi
else
  ACTUAL_SHA256="（网关未设置校验摘要）"
fi

# 两种包形态都支持：tarball 是发布产物（内含 artifacts/wist-agentd 与 artifacts/wist-exec，
# 执行器必须与守护进程同级），裸二进制是网关自身分发的默认包（只有 wist-agentd）。
if tar tzf "$PACKAGE_FILE" >/dev/null 2>&1; then
  PACKAGE_FORM="tarball"
else
  PACKAGE_FORM="裸二进制"
fi
note "形态 $PACKAGE_FORM · sha256 $ACTUAL_SHA256"

step "[2/4] 安装二进制到 $(short "$BIN_DIR")"
# 一律「先写同目录新文件、再 rename 覆盖」：直接 cp 到正在运行的二进制上会把那个路径改坏
# （macOS 上之后每次 exec 都被 SIGKILL），而 rename 只换目录项、不动老 inode，重装/升级安全。
install_bin() {
  cp -f "$1" "$BIN_DIR/$2.new"
  chmod 0755 "$BIN_DIR/$2.new"
  mv -f "$BIN_DIR/$2.new" "$BIN_DIR/$2"
  note "$(short "$BIN_DIR/$2")"
}

if [ "$PACKAGE_FORM" = "tarball" ]; then
  EXTRACT_DIR="$(mktemp -d)"
  tar xzf "$PACKAGE_FILE" -C "$EXTRACT_DIR"
  for BIN_NAME in wist-agentd wist-exec; do
    SRC="$(find "$EXTRACT_DIR" -type f -name "$BIN_NAME" | head -n 1)"
    if [ -z "$SRC" ]; then
      bad "agent package is missing $BIN_NAME"
      echo "  安装包里没有 ${BIN_NAME}，包发布不完整；已中止。" >&2
      exit 1
    fi
    install_bin "$SRC" "$BIN_NAME"
  done
else
  install_bin "$PACKAGE_FILE" "wist-agentd"
fi

step "[3/4] 写入初始配置"
if ! curl -fsSL --cacert "$CA_CERT" -H "authorization: Bearer $WIST_ENROLLMENT_TOKEN" "{{AGENT_INITIAL_CONFIG_URL}}" -o "$CONFIG_DIR/agentd.toml"; then
  bad "下载初始配置失败：见上方 curl 报错。"
  exit 1
fi
chmod 0600 "$CONFIG_DIR/agentd.toml"
note "$(short "$CONFIG_DIR/agentd.toml")（0600，注册成功后 token 会被清掉）"

step "[4/4] 注册常驻服务（${SERVICE_MANAGER}，${SERVICE_SCOPE_ARG}）"
if [ "${WIST_AGENTD_SERVICE:-1}" != "1" ]; then
  note "已跳过注册（WIST_AGENTD_SERVICE=0）"
  note "自行注册：$BIN_DIR/wist-agentd service install $SERVICE_SCOPE_ARG --config-dir \"$CONFIG_DIR\""
  note "或前台运行：$BIN_DIR/wist-agentd --config-dir \"$CONFIG_DIR\""
  exit 0
fi

# 一次性 token 只走命令行，不落盘；先注册再落服务定义——token 无效或控制面不可达时，
# 不会留下一个启动即报错的半成品服务。--force 让重复执行等价于升级（换二进制后必须重建
# 服务进程才会生效）。
TOOL_OUT="$(mktemp "${TMPDIR:-/tmp}/wist-service.XXXXXX")"
if ! "$BIN_DIR/wist-agentd" service install "$SERVICE_SCOPE_ARG" \
  --bin "$BIN_DIR/wist-agentd" \
  --config-dir "$CONFIG_DIR" \
  --enrollment-token "$WIST_ENROLLMENT_TOKEN" \
  --force >"$TOOL_OUT" 2>&1; then
  show_tool_output "$TOOL_OUT" >&2
  printf '\n' >&2
  bad "注册常驻服务失败：见上方输出。二进制与配置已就位，重跑本脚本即可重试。"
  exit 1
fi
show_tool_output "$TOOL_OUT"

printf '\n%s安装完成：wist-agentd 已交给 %s 托管，当前在后台持续运行%s\n' "$GREEN" "$SERVICE_MANAGER" "$RESET"
