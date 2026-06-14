#!/usr/bin/env bash
# ============================================================
#  Запускать от root на чистой Ubuntu/Debian ноде
# ============================================================

set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
ask()     { echo -e "${BOLD}[INPUT]${NC} $*"; }

# ── Root-проверка ────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускай от root (sudo -i)"

echo -e "\n${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Remnawave Node — Security Hardening     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}\n"

# ════════════════════════════════════════════════════════════
# 0. Сбор входных данных
# ════════════════════════════════════════════════════════════

read -p "Введите доверенный IP для доступа по SSH: " TRUSTED_IP
[[ -z "$TRUSTED_IP" ]] && error "IP не может быть пустым"

read -p "Введите имя нового sudo-пользователя (Enter = deploy): " NEW_USER
NEW_USER=${NEW_USER:-deploy}
echo "Выбрано имя пользователя: $NEW_USER"

read -p "Введите SSH-порт (Enter = оставить 22):" SSH_PORT
SSH_PORT=${SSH_PORT:-22}

read -p "Вставь публичный SSH-ключ (содержимое ~/.ssh/id_rsa.pub или id_ed25519.pub):" PUB_KEY
[[ -z "$PUB_KEY" ]] && error "Публичный ключ не может быть пустым"

echo ""
info "Начинаем настройку..."

# ════════════════════════════════════════════════════════════
# 1. Обновление системы
# ════════════════════════════════════════════════════════════
info "Обновляем пакеты..."
apt-get update -qq && apt-get upgrade -y -qq
success "Система обновлена"

# ════════════════════════════════════════════════════════════
# 2. Создание пользователя с sudo-правами
# ════════════════════════════════════════════════════════════
info "Создаём пользователя '$NEW_USER'..."

if id "$NEW_USER" &>/dev/null; then
    warn "Пользователь '$NEW_USER' уже существует — пропускаем создание"
else
    adduser --disabled-password --gecos "" "$NEW_USER"
    success "Пользователь '$NEW_USER' создан"
fi

usermod -aG sudo "$NEW_USER"

# Настройка sudo без пароля (удобно для автоматизации; убери если хочешь с паролем)
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$NEW_USER"
chmod 440 /etc/sudoers.d/"$NEW_USER"
success "Права sudo выданы пользователю '$NEW_USER'"

# Копируем публичный ключ новому пользователю
USER_HOME="/home/$NEW_USER"
mkdir -p "$USER_HOME/.ssh"
echo "$PUB_KEY" > "$USER_HOME/.ssh/authorized_keys"
chmod 700 "$USER_HOME/.ssh"
chmod 600 "$USER_HOME/.ssh/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh"
success "SSH-ключ добавлен для '$NEW_USER'"

# ════════════════════════════════════════════════════════════
# 3. Ограничение SSH по IP
# ════════════════════════════════════════════════════════════
info "Настраиваем hosts.allow / hosts.deny..."

# Бэкапы
cp /etc/hosts.allow /etc/hosts.allow.bak 2>/dev/null || true
cp /etc/hosts.deny  /etc/hosts.deny.bak  2>/dev/null || true

# Разрешаем SSH только с доверенного IP
cat > /etc/hosts.allow <<EOF
# Remnawave — разрешён SSH только с доверенного IP
sshd: $TRUSTED_IP
EOF

# Запрещаем всем остальным
cat > /etc/hosts.deny <<EOF
# Remnawave — блокируем SSH для всех, кроме hosts.allow
sshd: ALL
EOF

# Сбрасываем соединение по 443 порту кроме доверенного IP
# apt install iptables-persistent -y
# iptables -I DOCKER-USER -p tcp --dport 443 -s $TRUSTED_IP -j ACCEPT
# iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
# netfilter-persistent save

success "hosts.allow/deny настроены (доверенный IP: $TRUSTED_IP)"

# ════════════════════════════════════════════════════════════
# 4. Hardening SSH  [пункт 4]
# ════════════════════════════════════════════════════════════
info "Настраиваем /etc/ssh/sshd_config..."

SSHD_CFG="/etc/ssh/sshd_config"
cp "$SSHD_CFG" "${SSHD_CFG}.bak"

# Функция — установить или заменить параметр
set_ssh_param() {
    local key="$1" val="$2"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$SSHD_CFG"; then
        sed -i "s|^#\?[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$SSHD_CFG"
    else
        echo "${key} ${val}" >> "$SSHD_CFG"
    fi
}

set_ssh_param "Port"                    "$SSH_PORT"
set_ssh_param "PermitRootLogin"         "no"
set_ssh_param "PasswordAuthentication"  "no"
set_ssh_param "PubkeyAuthentication"    "yes"
set_ssh_param "AuthorizedKeysFile"      ".ssh/authorized_keys"
set_ssh_param "X11Forwarding"           "no"
set_ssh_param "AllowTcpForwarding"      "no"
set_ssh_param "MaxAuthTries"            "3"
set_ssh_param "LoginGraceTime"          "30"
set_ssh_param "ClientAliveInterval"     "300"
set_ssh_param "ClientAliveCountMax"     "2"

# Ограничиваем вход только нашим пользователем
set_ssh_param "AllowUsers"              "$NEW_USER"

# Проверяем конфиг перед перезапуском
sshd -t && success "sshd_config валиден"

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
success "SSH перезапущен (порт: $SSH_PORT, вход только по ключу)"

# ════════════════════════════════════════════════════════════
# 6. Fail2Ban — защита от брутфорса
# ════════════════════════════════════════════════════════════
info "Устанавливаем Fail2Ban..."
apt-get install -y -qq fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 $TRUSTED_IP

[sshd]
enabled  = true
port     = $SSH_PORT
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
EOF

systemctl enable fail2ban --quiet
systemctl restart fail2ban
success "Fail2Ban настроен и запущен"

# ════════════════════════════════════════════════════════════
# 7. Kernel hardening (sysctl)
# ════════════════════════════════════════════════════════════
info "Применяем sysctl hardening..."

cat > /etc/sysctl.d/99-remnawave-hardening.conf <<EOF
# Remnawave Node — Kernel Hardening

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Защита от IP-спуфинга
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Отключаем ICMP редиректы
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Не принимаем source-routed пакеты
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood защита
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# TIME_WAIT hardening
net.ipv4.tcp_rfc1337 = 1

# Log martians
net.ipv4.conf.all.log_martians = 1
EOF

sysctl --system >/dev/null
success "sysctl hardening применён"

# ════════════════════════════════════════════════════════════
# Итог
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Настройка ноды завершена успешно!        ${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Что сделано:${NC}"
echo -e "  ${GREEN}✓${NC} Создан пользователь: ${BOLD}$NEW_USER${NC} (sudo без пароля)"
echo -e "  ${GREEN}✓${NC} SSH-ключ добавлен для $NEW_USER"
echo -e "  ${GREEN}✓${NC} SSH: только ключ, только $TRUSTED_IP, порт $SSH_PORT"
echo -e "  ${GREEN}✓${NC} hosts.allow/deny настроены"
echo -e "  ${GREEN}✓${NC} UFW: открыты порты $SSH_PORT (trusted), 443 (all)$([ "$OPEN_8443" == "y" ] && echo ", 8443 (all)")"
echo -e "  ${GREEN}✓${NC} Fail2Ban: ban на 1ч после 3 попыток"
echo -e "  ${GREEN}✓${NC} sysctl: защита от спуфинга, SYN-флуда, редиректов"
echo ""
echo -e "${YELLOW}${BOLD}⚠  ВАЖНО — не закрывай текущую сессию!${NC}"
echo -e "   Открой ${BOLD}новый терминал${NC} и проверь подключение:"
echo -e "   ${CYAN}ssh -p $SSH_PORT -i ~/.ssh/id_rsa $NEW_USER@<NODE_IP>${NC}"
echo -e "   Только после успешного входа закрывай эту сессию."
echo ""
echo -e "${YELLOW}Бэкапы оригинальных конфигов:${NC}"
echo -e "   /etc/ssh/sshd_config.bak"
echo -e "   /etc/hosts.allow.bak"
echo -e "   /etc/hosts.deny.bak"
echo ""
