#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<EOF
Использование: $0 root@IP [--domain dns.example.com] [--email you@mail] [--public] [--secure-ssh]
--secure-ssh: положить на сервер SSH-ключ этого компьютера и запретить вход по паролю.
Нестандартный порт SSH: SSH_PORT=2222 $0 root@IP
EOF
  exit 1
fi
TARGET="$1"; shift
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECURE_SSH=0
PASS=()
for a in "$@"; do
  if [[ "$a" == "--secure-ssh" ]]; then SECURE_SSH=1; else PASS+=("$a"); fi
done
set -- ${PASS[@]+"${PASS[@]}"}

SOCK="$(mktemp -u "${TMPDIR:-/tmp}/redns-ssh.XXXXXX")"
PORT="${SSH_PORT:-22}"
SSH=(ssh -p "$PORT" -o ControlMaster=auto -o ControlPath="$SOCK" -o ControlPersist=120 -o StrictHostKeyChecking=accept-new)
WORK="$(mktemp -d)"
cleanup() { ssh -p "$PORT" -o ControlPath="$SOCK" -O exit "$TARGET" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> Подключаюсь к $TARGET"
case "$("${SSH[@]}" "$TARGET" uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Неподдерживаемая архитектура" >&2; exit 1 ;;
esac

command -v go >/dev/null || { echo "Нужен Go: https://go.dev/dl/" >&2; exit 1; }
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || date +%Y.%m.%d)"
echo "==> Собираю redns $VERSION для linux/$ARCH"
mkdir -p "$WORK/redns/deploy"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" -o "$WORK/redns/redns-linux-$ARCH" ./cmd/redns)
cp -R "$ROOT/lists" "$WORK/redns/"
cp "$ROOT/config.example.yaml" "$WORK/redns/"
cp "$ROOT/deploy/install.sh" "$ROOT/deploy/redns.service" "$ROOT/deploy/sysctl.conf" "$WORK/redns/deploy/"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$WORK" -czf "$WORK/redns.tgz" redns 2>/dev/null || tar -C "$WORK" -czf "$WORK/redns.tgz" redns

echo "==> Загружаю"
"${SSH[@]}" "$TARGET" 'rm -rf /tmp/redns-install && mkdir -p /tmp/redns-install'
scp -q -P "$PORT" -o ControlPath="$SOCK" "$WORK/redns.tgz" "$TARGET:/tmp/redns-install/"

if [[ $SECURE_SSH -eq 1 ]]; then
  KEY="$HOME/.ssh/id_ed25519"
  if [[ ! -f "$KEY" ]]; then
    echo "==> Создаю SSH-ключ $KEY"
    mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
    ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C "redns-$(hostname -s)"
  fi
  PUB="$(cat "$KEY.pub")"
  "${SSH[@]}" "$TARGET" "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF '$PUB' ~/.ssh/authorized_keys || echo '$PUB' >> ~/.ssh/authorized_keys"
  if ssh -p "$PORT" -i "$KEY" -o ControlPath=none -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=accept-new "$TARGET" true 2>/dev/null; then
    echo "==> Вход по ключу работает, отключаю вход по паролю"
    set -- "$@" --ssh-key-only
  else
    echo "Вход по ключу не заработал, пароль оставляю" >&2
  fi
fi

ARGS=""
for a in "$@"; do ARGS+=" $(printf '%q' "$a")"; done
SUDO=""
[[ "${TARGET%%@*}" == "root" ]] || SUDO="sudo"
"${SSH[@]}" -t "$TARGET" "cd /tmp/redns-install && tar xzf redns.tgz && $SUDO bash redns/deploy/install.sh$ARGS"
