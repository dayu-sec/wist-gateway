#!/usr/bin/env sh
set -eu

ARCH="{{ARCH}}"
AGENT_PACKAGE_SHA256="{{AGENT_PACKAGE_SHA256}}"
if [ -z "${WARP_INSIGHT_ENROLLMENT_TOKEN:-}" ]; then
  if [ -r /dev/tty ]; then
    printf "Enrollment token: " >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    IFS= read -r WARP_INSIGHT_ENROLLMENT_TOKEN </dev/tty
    stty echo </dev/tty 2>/dev/null || true
    printf "\n" >/dev/tty
  fi
fi
if [ -z "${WARP_INSIGHT_ENROLLMENT_TOKEN:-}" ]; then
  echo "missing WARP_INSIGHT_ENROLLMENT_TOKEN" >&2
  exit 1
fi
if [ -z "${WARP_INSIGHT_HOME:-}" ]; then
  OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
  if [ "$(id -u)" = "0" ]; then
    case "$OS_NAME" in
      Darwin) WARP_INSIGHT_HOME="/usr/local/warp-insight" ;;
      *) WARP_INSIGHT_HOME="/opt/warp-insight" ;;
    esac
  else
    WARP_INSIGHT_HOME="$HOME/.warp-insight"
  fi
fi
BIN_DIR="$WARP_INSIGHT_HOME/bin"
CONFIG_DIR="$WARP_INSIGHT_HOME/.wist-agentd"

umask 077
mkdir -p "$BIN_DIR" "$CONFIG_DIR"
chmod 0700 "$CONFIG_DIR"

# Trust the admin CA embedded in this signed script so the package and initial
# config downloads below are verified against it. This script itself was
# signature-verified by the bootstrap command, so the embedded CA is a valid
# trust anchor (no -k needed for these sensitive downloads).
CA_CERT="$(mktemp)"
cat >"$CA_CERT" <<'EOF'
{{TRUST_BUNDLE}}
EOF
chmod 0600 "$CA_CERT"
trap 'rm -f "$CA_CERT"' EXIT INT TERM

curl -fsSL --cacert "$CA_CERT" -H "authorization: Bearer $WARP_INSIGHT_ENROLLMENT_TOKEN" "{{AGENT_PACKAGE_URL}}" -o "$BIN_DIR/wist-agentd"
if [ -n "$AGENT_PACKAGE_SHA256" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(sha256sum "$BIN_DIR/wist-agentd" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA256="$(shasum -a 256 "$BIN_DIR/wist-agentd" | awk '{print $1}')"
  else
    echo "missing sha256sum or shasum for package verification" >&2
    exit 1
  fi
  if [ "$ACTUAL_SHA256" != "$AGENT_PACKAGE_SHA256" ]; then
    echo "agent package sha256 mismatch: expected $AGENT_PACKAGE_SHA256 got $ACTUAL_SHA256" >&2
    exit 1
  fi
fi
chmod 0755 "$BIN_DIR/wist-agentd"

curl -fsSL --cacert "$CA_CERT" -H "authorization: Bearer $WARP_INSIGHT_ENROLLMENT_TOKEN" "{{AGENT_INITIAL_CONFIG_URL}}" -o "$CONFIG_DIR/agentd.toml"
chmod 0600 "$CONFIG_DIR/agentd.toml"

echo "wist-agentd installed for $ARCH"
echo "binary: $BIN_DIR/wist-agentd"
echo "config: $CONFIG_DIR/agentd.toml"
echo "start:  $BIN_DIR/wist-agentd --config-dir $CONFIG_DIR"

if [ "${WARP_INSIGHT_START:-0}" = "1" ]; then
  exec "$BIN_DIR/wist-agentd" --config-dir "$CONFIG_DIR"
fi
