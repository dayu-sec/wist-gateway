#!/usr/bin/env sh
# wist-agentd 安装脚本（由 wist-gateway 渲染签名后下发，本文件已被签名校验过）。
#
# 顺序：装包并校验摘要 → 装二进制 → 写初始配置 → 注册常驻服务（交给 launchd / systemd）。
# 幂等：重跑等价于升级（覆盖二进制 + 重建服务进程）；任何一步失败都会明确说明停在哪。
#
# 两种模式（WIST_AGENTD_REINSTALL 选）：
#   * 首次安装 / 升级（默认）：没注册过时用一次性 token 完成注册，再交给常驻服务托管。
#     已在册的机器重跑只换二进制、配置并重建服务 —— **本机已有的客户端证书不会被换**
#     （注册会被跳过：`ensure_enrolled` 见到 state 里已有身份就早返回）。
#   * 重装（WIST_AGENTD_REINSTALL=1）：**替换本机的客户端证书**。先停旧服务，写完配置后用
#     `wist-agentd enroll --force` 丢掉本机旧身份（凭据 state + 客户端证书 + 续期台账）、
#     凭 token 重交 CSR 换一张新证书，再重建服务。用于：证书已过期、换过网关、本机身份错乱。
#     保留本机私钥（私钥是耗材，「身份」才是网关签出来的东西）；agent_id 是机器标识的稳定
#     哈希，重装后不变，也不影响其它机器。
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
    --reinstall)
      WIST_AGENTD_REINSTALL=1
      shift
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
# 重装模式开关，默认关。页面在「重装」模式下会在这条命令前导出 WIST_AGENTD_REINSTALL=1；
# 自我提权时用 `--reinstall` 参数回传（sudo 会清掉环境变量）。
REINSTALL="${WIST_AGENTD_REINSTALL:-0}"

OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"
# macOS 上 `uname -m` 报的是**当前进程**的架构：在 Rosetta 下跑会给出 x86_64，而机器其实是 Apple
# Silicon —— 那会让下面的平台校验把一份合法的 macOS 包装成「平台不符」拒掉。硬件架构问 sysctl：
# `hw.optional.arm64 = 1` 即 Apple Silicon（与是否在 Rosetta 下无关）；Intel 机上该键不存在。
if [ "$OS_NAME" = "Darwin" ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
  HOST_ARCH="arm64"
fi
# 包是**按平台**发布的：`ARCH` 是网关渲染时就定死的 target-triple，`[1/4]` 取的就是这个平台的制品。
# 装错平台不是「跑不起来」那么简单：Linux 的 ELF 盖到 macOS 上，会把跑得好好的 agentd 换成一个
# 无法执行的文件，而且要拖到第 4 步才报错（那时二进制已被换掉、旧服务也已经动过）。
# 所以这是脚本做的**第一件事**：在提权之前、下载之前、写任何文件之前先核对本机 —— 不匹配就
# 就地拒绝，一个字节都不写。
case "{{ARCH}}" in
  *-apple-darwin) EXPECT_OS="Darwin"; EXPECT_ARCH="arm64" ;;
  x86_64-*-linux-*) EXPECT_OS="Linux"; EXPECT_ARCH="x86_64" ;;
  aarch64-*-linux-*) EXPECT_OS="Linux"; EXPECT_ARCH="aarch64" ;;
  *) EXPECT_OS=""; EXPECT_ARCH="" ;;
esac
# arm64 与 aarch64 是同一颗芯片的两种写法（macOS 用前者、Linux 用后者）。
ARCH_ALIAS="$HOST_ARCH"
case "$HOST_ARCH" in arm64) ARCH_ALIAS="aarch64" ;; esac
EXPECT_ALIAS="$EXPECT_ARCH"
case "$EXPECT_ARCH" in arm64) EXPECT_ALIAS="aarch64" ;; esac
if [ -n "$EXPECT_OS" ] && { [ "$OS_NAME" != "$EXPECT_OS" ] || [ "$ARCH_ALIAS" != "$EXPECT_ALIAS" ]; }; then
  printf '%s\n' "这份安装命令是给 {{ARCH}} 的，但本机是 ${OS_NAME} ${HOST_ARCH} —— 已中止，未做任何改动。" >&2
  printf '%s\n' "请在网关「安装 Agent」页按「目标主机」选对应那一栏的命令（macOS 与 Linux 不能混用）。" >&2
  exit 2
fi

case "$OS_NAME" in
  Darwin) SERVICE_MANAGER="launchd" ;;
  Linux) SERVICE_MANAGER="systemd" ;;
  *) SERVICE_MANAGER="服务管理器" ;;
esac

# 只装**系统级**：开机自起（不依赖登录）、以 root 运行、能读 /var/log 等受限路径。
# agentd 自 0.4.0 起只保留系统级托管，`service` 子命令不再接受任何作用域旗标（系统级即默认
# 且唯一）—— 所以这里一律不传作用域参数（0.3.x 上省略它同样落系统级）。
#
# 系统级配置目录只能是 /etc/wist-agentd：agentd 只把该目录（及其子目录）认作系统级
# （`is_system_config_dir`），并据此把数据放 /var/lib/wist-agentd、日志放 /var/log/wist-agentd。
# 落到别处就不再是系统级布局，run/state/spool 与日志会退回配置目录下。
#
# 系统级由脚本自己提权，而不是要求使用者手工加 sudo：手工加 sudo 会清掉 token 所在的
# 环境变量，token 静默丢失、脚本退到交互提示。重新执行自己时把 token 与重装标记作为参数带过去。
if [ "$(id -u)" != "0" ]; then
  if [ ! -f "$0" ] || { [ ! -t 0 ] && [ ! -r /dev/tty ]; }; then
    printf '%s\n' "系统级安装需要 root：请用 sudo 重跑本脚本。" >&2
    exit 2
  fi
  if [ "${REINSTALL}" = "1" ]; then
    exec sudo -p '系统级安装需要管理员权限: ' sh "$0" --reinstall --enrollment-token "$WIST_ENROLLMENT_TOKEN" "$@"
  fi
  exec sudo -p '系统级安装需要管理员权限: ' sh "$0" --enrollment-token "$WIST_ENROLLMENT_TOKEN" "$@"
fi
# 二进制放标准 bin 目录，与配置目录解耦；配置目录只放 config + tasks。
# （系统级下 state/run/spool 落 /var/lib/wist-agentd、日志落 /var/log/wist-agentd。）
WIST_AGENTD_HOME="${WIST_AGENTD_HOME:-/etc/wist-agentd}"
BIN_DIR="${WIST_AGENTD_BIN_DIR:-/usr/local/bin}"
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
if [ "${REINSTALL}" = "1" ]; then
  printf '  模式    %s\n' "重装（替换本机客户端证书）"
else
  printf '  模式    %s\n' "首次安装 / 升级"
fi
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
# 外部工具的输出统一收在这里（自检、注册、服务三步共用），出错时原样展示给操作者。
TOOL_OUT="$(mktemp "${TMPDIR:-/tmp}/wist-tool.XXXXXX")"
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

# 两种包形态都支持：tarball 是发布产物（`sysrun/package-agentd.sh` 打的那份：一层
# `wist-agentd-<版本>-<target>/` 里放 wist-agentd / wist-exec / wist-upgrader 三件），
# 裸二进制是网关自身分发的默认包（只有 wist-agentd：执行器与升级器都不在，只能采集/上报）。
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
  # 三个二进制必须一起换：升级器正好是去换 agentd 自己的那个进程，版本错配就没有「同版本」前提。
  for BIN_NAME in wist-agentd wist-exec wist-upgrader; do
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
  note "裸二进制包不含 wist-exec / wist-upgrader：执行类与升级类工作在这台机器上会失败"
fi

# 装上去的二进制必须能在这台机器上真的跑起来：平台不对 / 包损坏 / 丢了执行位，都在这里就明确拦住 ——
# 而不是拖到第 4 步（那时旧服务已停、报错也更难对上原因）。
if ! "$BIN_DIR/wist-agentd" version >"$TOOL_OUT" 2>&1; then
  show_tool_output "$TOOL_OUT" >&2
  printf '\n' >&2
  bad "装上去的 wist-agentd 跑不起来（平台不对 / 包损坏）。"
  printf '%s\n' "  注意：$BIN_DIR 下的二进制已被本次安装替换；请用与目标主机匹配的平台的安装命令重跑。" >&2
  exit 1
fi
note "自检通过：$(short "$BIN_DIR/wist-agentd") version"

step "[3/4] 写入初始配置"
if ! curl -fsSL --cacert "$CA_CERT" -H "authorization: Bearer $WIST_ENROLLMENT_TOKEN" "{{AGENT_INITIAL_CONFIG_URL}}" -o "$CONFIG_DIR/agentd.toml"; then
  bad "下载初始配置失败：见上方 curl 报错。"
  exit 1
fi
chmod 0600 "$CONFIG_DIR/agentd.toml"
note "$(short "$CONFIG_DIR/agentd.toml")（0600，注册成功后 token 会被清掉）"

if [ "${REINSTALL}" = "1" ]; then
  step "[4/4] 替换客户端证书并重建服务（${SERVICE_MANAGER}）"
else
  step "[4/4] 注册常驻服务（${SERVICE_MANAGER}）"
fi

# 一次性 token 只走命令行，不落盘。
# 首次安装 / 升级：注册与落服务定义同一步（`service install --enrollment-token`）—— token
#   无效或控制面不可达时不会留下启动即报错的半成品服务；已在册的机器上注册会被跳过。
# 重装：**先停旧服务、再换证书**（`enroll --force`，这一步才是「替换客户端证书」），
#   最后落服务定义 —— 此时身份已就位，装服务那一步不再需要 token。
# 顺序上两点讲究：
#   * 停服务放在**这里**（不放到更早的步骤）：前面几步只是换二进制与写配置，失败了机器上在
#     跑的 agentd 不受影响；到这一步才是「不可回头」的点。
#   * 换证书放在 `WIST_AGENTD_SERVICE` 早退（跳过注册）**之前**：跳过注册是「自己决定怎么跑」
#     的逃生口，不该顺手把「替换证书」这件事也跳过去。
# --force 让重复执行等价于升级（换二进制后必须重建服务进程才会生效）。
if [ "${REINSTALL}" = "1" ]; then
  # 换证书前先停掉在跑的 agentd：否则它可能在新证书落盘之后又把旧状态写回去。
  # 停不掉要**说出来**（可能本机本来就没装过服务，也可能是别的毛病）—— 不能把「停不掉」
  # 讲成「本来就没有」：那正好把真正的故障藏起来。为了不阻断「服务已手工停掉」这种常见情形，
  # 这里不中止，只把原样输出摆出来。
  if ! "$BIN_DIR/wist-agentd" service uninstall --config-dir "$CONFIG_DIR" >"$TOOL_OUT" 2>&1; then
    note "重装模式：停止 / 移除旧服务定义没成功；原样如下（本机本来就没装过服务时，这也算正常）"
    show_tool_output "$TOOL_OUT"
  else
    note "重装模式：旧服务已停止并移除定义（下面重建）"
  fi
  if ! "$BIN_DIR/wist-agentd" enroll --force --config-dir "$CONFIG_DIR" \
    --token "$WIST_ENROLLMENT_TOKEN" >"$TOOL_OUT" 2>&1; then
    show_tool_output "$TOOL_OUT" >&2
    printf '\n' >&2
    bad "重新注册失败：见上方输出。重装不会自动回滚 —— 若上面这一步已经丢掉了本机旧身份，它会停在未注册状态。"
    printf '%s\n' "  修好上面那个原因后重跑本脚本即可重建；token 若已被用掉，换一条新的。" >&2
    exit 1
  fi
  show_tool_output "$TOOL_OUT"
fi

if [ "${WIST_AGENTD_SERVICE:-1}" != "1" ]; then
  note "已跳过注册（WIST_AGENTD_SERVICE=0）"
  note "自行注册：$BIN_DIR/wist-agentd service install --config-dir \"$CONFIG_DIR\""
  note "或前台运行：$BIN_DIR/wist-agentd --config-dir \"$CONFIG_DIR\""
  if [ "${REINSTALL}" = "1" ]; then
    note "客户端证书已按重装模式替换（只跳过了常驻服务注册）。"
  fi
  exit 0
fi

# 装服务那一步：重装模式下身份已就位，不再需要 token。
service_install() {
  if [ "${REINSTALL}" = "1" ]; then
    "$BIN_DIR/wist-agentd" service install \
      --bin "$BIN_DIR/wist-agentd" \
      --config-dir "$CONFIG_DIR" \
      --force
  else
    "$BIN_DIR/wist-agentd" service install \
      --bin "$BIN_DIR/wist-agentd" \
      --config-dir "$CONFIG_DIR" \
      --enrollment-token "$WIST_ENROLLMENT_TOKEN" \
      --force
  fi
}
if ! service_install >"$TOOL_OUT" 2>&1; then
  show_tool_output "$TOOL_OUT" >&2
  printf '\n' >&2
  bad "注册常驻服务失败：见上方输出。二进制与配置已就位，重跑本脚本即可重试。"
  exit 1
fi
show_tool_output "$TOOL_OUT"

printf '\n%s安装完成：wist-agentd 已交给 %s 托管，当前在后台持续运行%s\n' "$GREEN" "$SERVICE_MANAGER" "$RESET"
if [ "${REINSTALL}" = "1" ]; then
  note "重装模式：本机客户端证书已替换；agent_id 是机器标识的稳定哈希，保持不变。"
fi
