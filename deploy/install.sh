#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
EMAIL=""
MODE="private"
IPV4=""
IPV6="auto"
SKIP_SYSCTL=0
ACME_STAGING=0
FIREWALL=1
SSH_KEY_ONLY=0
GO_FALLBACK_VERSION="go1.26.9"
CONFIG=/etc/redns/config.yaml

die()  { echo -e "\033[31mОшибка:\033[0m $*" >&2; exit 1; }
warn() { echo -e "\033[33mВнимание:\033[0m $*" >&2; }
info() { echo -e "\033[36m==>\033[0m $*"; }
usage() {
  cat <<EOF
Использование: sudo $0 [--domain dns.example.com] [--email you@mail] [--public]
               [--ipv4 IP] [--ipv6 IP | --no-ipv6] [--no-sysctl] [--no-firewall]
               [--ssh-key-only] [--acme-staging]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --public) MODE="public"; shift ;;
    --ipv4) IPV4="${2:-}"; shift 2 ;;
    --ipv6) IPV6="${2:-}"; shift 2 ;;
    --no-ipv6) IPV6=""; shift ;;
    --no-sysctl) SKIP_SYSCTL=1; shift ;;
    --acme-staging) ACME_STAGING=1; shift ;;
    --no-firewall) FIREWALL=0; shift ;;
    --ssh-key-only) SSH_KEY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "неизвестный аргумент $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "запусти от root: sudo $0 $*"
command -v systemctl >/dev/null || die "нужен systemd"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$SRC/config.example.yaml" ]] || die "не найден $SRC/config.example.yaml"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "неподдерживаемая архитектура $(uname -m)" ;;
esac

info "Пакеты"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
apt-get update -qq
apt-get install -y -qq ca-certificates curl dnsutils iproute2 qrencode ufw fail2ban unattended-upgrades >/dev/null

BIN=""
for c in "$SRC/redns-linux-$ARCH" "$SRC/redns" "$SRC/dist/redns-linux-$ARCH"; do
  if [[ -f "$c" ]] && "$c" version >/dev/null 2>&1; then BIN="$c"; break; fi
done
if [[ -z "$BIN" ]]; then
  [[ -f "$SRC/go.mod" ]] || die "нет бинарника redns и исходников для сборки"
  if ! command -v go >/dev/null && [[ ! -x /usr/local/go/bin/go ]]; then
    info "Скачиваю Go"
    GOV="$(curl -fsSL 'https://go.dev/dl/?mode=json' | grep -o '"version": *"go[0-9.]*"' | head -1 | grep -o 'go[0-9.]*' || true)"
    GOV="${GOV:-$GO_FALLBACK_VERSION}"
    curl -fsSL "https://go.dev/dl/${GOV}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
  fi
  export PATH="/usr/local/go/bin:$PATH"
  info "Собираю redns ($(go version | awk '{print $3}'))"
  (cd "$SRC" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=src-$(date +%Y%m%d)" -o "$SRC/redns-linux-$ARCH" ./cmd/redns)
  BIN="$SRC/redns-linux-$ARCH"
fi
info "Версия: $("$BIN" version)"

detect4() {
  local ip
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    ip="$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]')" || true
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
  done
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
}
detect6() {
  local ip
  ip -6 addr show scope global 2>/dev/null | grep -q inet6 || return 0
  ip="$(curl -6 -fsS --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d '[:space:]')" || true
  [[ "$ip" == *:* ]] && echo "$ip"
}
[[ -n "$IPV4" ]] || IPV4="$(detect4)"
[[ -n "$IPV4" ]] || die "не удалось определить публичный IPv4, передай --ipv4"
if [[ "$IPV6" == "auto" ]]; then IPV6="$(detect6 || true)"; fi
info "IP: $IPV4${IPV6:+, $IPV6}"

CUR_HOST=""
if [[ -f $CONFIG ]]; then
  CUR_HOST="$(grep -m1 '^hostname:' $CONFIG | sed -E 's/^hostname: *"?([^"]*)"?.*/\1/')"
fi
[[ -n "$DOMAIN" ]] || DOMAIN="$CUR_HOST"
if [[ -z "$DOMAIN" ]]; then
  DOMAIN="${IPV4//./-}.sslip.io"
  warn "домен не указан, беру $DOMAIN. Свой домен надёжнее: --domain dns.example.com"
fi
DOMAIN="${DOMAIN,,}"
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$DOMAIN" == *.* ]] || die "плохой домен $DOMAIN"

RESOLVED="$(dig +short A "$DOMAIN" @1.1.1.1 2>/dev/null | tail -1 || true)"
if [[ "$RESOLVED" != "$IPV4" ]]; then
  warn "A-запись $DOMAIN = '${RESOLVED:-нет}', нужна $IPV4. Сертификат выпустится, когда запись появится."
fi

if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/redns.conf
  systemctl restart systemd-resolved
  if ! ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null; then
    cat /run/systemd/resolve/resolv.conf > /etc/resolv.conf 2>/dev/null || true
  fi
fi
if ! grep -qE '^nameserver +[0-9a-f]' /etc/resolv.conf 2>/dev/null || grep -qE '^nameserver +127\.0\.0\.5[34]' /etc/resolv.conf; then
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi
for p in 53 80 443 853; do
  holder="$(ss -H -ltnup "sport = :$p" 2>/dev/null | grep -v '"redns"' | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2 || true)"
  [[ -z "$holder" ]] || die "порт $p занят процессом '$holder'. Останови его (systemctl disable --now $holder) и запусти снова."
done

id redns >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /var/lib/redns --shell /usr/sbin/nologin redns
install -m 0755 "$BIN" /usr/local/bin/redns.new && mv -f /usr/local/bin/redns.new /usr/local/bin/redns

install -d -m 0755 /etc/redns /etc/redns/lists
for f in "$SRC"/lists/*.txt; do
  name="$(basename "$f")"
  if [[ "$name" == "custom.txt" && -f /etc/redns/lists/custom.txt ]]; then continue; fi
  install -m 0644 "$f" "/etc/redns/lists/$name"
done
install -d -o redns -g redns -m 0750 /var/lib/redns /var/lib/redns/certs /var/lib/redns/lists

if [[ ! -f $CONFIG ]]; then
  TOKEN="$(/usr/local/bin/redns token)"
  sed -e "s|REDNS_HOSTNAME|$DOMAIN|" -e "s|REDNS_IPV4|$IPV4|" -e "s|REDNS_IPV6|$IPV6|" \
      -e "s|REDNS_TOKEN|$TOKEN|" -e "s|REDNS_EMAIL|$EMAIL|" -e "s|^  mode: private|  mode: $MODE|" \
      "$SRC/config.example.yaml" > $CONFIG
  if [[ $ACME_STAGING -eq 1 ]]; then
    sed -i 's|^  # acme_directory:|  acme_directory:|' $CONFIG
  fi
  info "Создан $CONFIG"
else
  info "Конфиг $CONFIG сохранён"
  if [[ "$DOMAIN" != "$CUR_HOST" ]]; then
    sed -i -E "s|^hostname:.*|hostname: \"$DOMAIN\"|" $CONFIG
    warn "имя сервера: $CUR_HOST → $DOMAIN. Профили на устройствах нужно поставить заново."
  fi
fi
ADMIN_PASS=""
if ! grep -qE '^[[:space:]]*password_hash:[[:space:]]*"\$2' $CONFIG; then
  ADMIN_PASS="$(/usr/local/bin/redns passwd -c $CONFIG -q)"
fi
chown root:redns $CONFIG
chmod 0640 $CONFIG
TOKEN="$(/usr/local/bin/redns key -q -c $CONFIG || true)"
MODE_NOW="$(grep -m1 -E '^  mode:' $CONFIG | awk '{print $2}')"

info "Проверяю конфиг и скачиваю списки"
runuser -u redns -- /usr/local/bin/redns check -c $CONFIG | tail -n 1

if [[ $SKIP_SYSCTL -eq 0 ]]; then
  modprobe tcp_bbr 2>/dev/null || true
  install -m 0644 "$SRC/deploy/sysctl.conf" /etc/sysctl.d/99-redns.conf
  sysctl --system >/dev/null 2>&1 || warn "часть sysctl не применилась (на OpenVZ/LXC это нормально)"
fi

info "Защита сервера"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/redns-sshd.local <<'JAIL'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
JAIL
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || warn "fail2ban не запустился"

if [[ $FIREWALL -eq 1 ]]; then
  SSH_PORTS="$(ss -H -ltnp 2>/dev/null | grep -E '"sshd"|"ssh"' | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u | tr '\n' ' ')"
  [[ -n "${SSH_CONNECTION:-}" ]] && SSH_PORTS="$SSH_PORTS $(echo "$SSH_CONNECTION" | awk '{print $4}')"
  [[ -n "${SSH_PORTS// /}" ]] || SSH_PORTS=22
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for p in $SSH_PORTS; do ufw limit "$p/tcp" >/dev/null; done
  for r in 53 80/tcp 443/tcp 853 9339/tcp 30000/tcp 4070/tcp; do ufw allow "$r" >/dev/null; done
  ufw reject proto udp from any to any port 443 >/dev/null || true
  ufw --force enable >/dev/null && info "Фаервол включён, SSH: $(echo $SSH_PORTS | tr ' ' '\n' | sort -u | tr '\n' ' ')" || warn "ufw не включился"
fi

if [[ $SSH_KEY_ONLY -eq 1 ]]; then
  if [[ -s /root/.ssh/authorized_keys ]]; then
    mkdir -p /etc/ssh/sshd_config.d
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/10-redns.conf
    if sshd -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
      info "SSH: вход только по ключу"
    else
      rm -f /etc/ssh/sshd_config.d/10-redns.conf
      warn "конфиг SSH не прошёл проверку, вход по паролю оставлен"
    fi
  else
    warn "в /root/.ssh/authorized_keys нет ключей, вход по паролю оставлен"
  fi
fi

install -m 0644 "$SRC/deploy/redns.service" /etc/systemd/system/redns.service
systemctl daemon-reload
systemctl enable redns >/dev/null 2>&1
systemctl restart redns
sleep 2
systemctl is-active --quiet redns || { journalctl -u redns -n 30 --no-pager; die "redns не запустился"; }

info "Жду сертификат (до 90 секунд)"
ok=0
for _ in $(seq 1 45); do
  if curl -fsS --max-time 3 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [[ $ok -eq 1 ]]; then
  info "HTTPS работает"
else
  warn "сертификата пока нет. Проверь A-запись $DOMAIN → $IPV4 и что порты 80/443 открыты. Логи: journalctl -u redns -f"
fi

SETUP="https://$DOMAIN/"
DOH="https://$DOMAIN/dns-query"
DOT_LINE="  DoT  $DOMAIN"
if [[ "$MODE_NOW" == "private" && -n "$TOKEN" ]]; then
  SETUP="https://$DOMAIN/setup/$TOKEN"
  DOH="https://$DOMAIN/dns-query/$TOKEN"
  DOT_LINE=""
fi
if [[ -n "$ADMIN_PASS" ]]; then
  ADMIN_LINE="пароль: $ADMIN_PASS  (покажу один раз, сохрани)"
else
  ADMIN_LINE="пароль прежний, сменить: sudo redns passwd"
fi
cat <<EOF

$(echo -e "\033[32mReDNS работает\033[0m")

  Настройка устройств:  $SETUP
  Админка:              https://$DOMAIN/admin
                        $ADMIN_LINE

  DoH  $DOH
${DOT_LINE}
  IP   $IPV4${IPV6:+, $IPV6}

  Ссылка с ключом даёт доступ к DNS, не публикуй её.
EOF
if command -v qrencode >/dev/null; then
  echo
  qrencode -t ansiutf8 -m 2 "$SETUP" | sed 's/^/  /'
fi
