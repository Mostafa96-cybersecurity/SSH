#!/usr/bin/env bash
# Secure SSH Access By Mostafa Mohamed
# One-shot hardening: user provisioning, SSH tightening, Fail2Ban strict policy.

set -Eeuo pipefail
IFS=$'\n\t'

# ===== UI Helpers =====
CEOL=$'\e[0m'
bold(){ printf '\e[1m%s\e[0m' "$*"; }
dim(){ printf '\e[2m%s\e[0m' "$*"; }
ok(){ echo -e "✅ $*"; }
warn(){ echo -e "⚠️  $*"; }
err(){ echo -e "❌ $*" >&2; }
hr(){ printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '─'; }

banner(){
  clear
  local title="Secure SSH Access"
  local by="By Mostafa Mohamed"
  echo
  echo -e "╔══════════════════════════════════════════════════════════════╗"
  printf  "║  %s  ║\n" "$(printf '%-58s' "$title")"
  printf  "║  %s  ║\n" "$(printf '%-58s' "$by")"
  echo -e "╚══════════════════════════════════════════════════════════════╝"
  echo
}

die(){ err "$*"; exit 1; }
trap 'err "Something went wrong. Check messages above."' ERR

require_root(){
  [[ $EUID -eq 0 ]] || die "Run as root (use sudo)."
}

# ===== System Checks =====
require_bins(){
  local bins=(sed awk grep cut getent id useradd usermod install chmod chown systemctl sshd)
  for b in "${bins[@]}"; do command -v "$b" >/dev/null || die "Missing required binary: $b"; done
}

# ===== Inputs / Prompts =====
prompt(){
  local msg="$1" def="${2:-}"
  local ans
  read -r -p "$msg ${def:+[$def]}: " ans
  echo "${ans:-$def}"
}

confirm(){
  local msg="$1"
  while true; do
    read -r -p "$msg [y/n]: " yn
    case "$yn" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
    esac
  done
}

# ===== SSHD Drop-in =====
write_sshd_dropin(){
  local port="$1" key_only="$2" lock_root="$3"
  local drop_dir="/etc/ssh/sshd_config.d"
  local drop_file="${drop_dir}/10-hardening.conf"

  mkdir -p "$drop_dir"
  local permit="prohibit-password"
  [[ "$lock_root" == "yes" ]] && permit="no"

  cat >"$drop_file" <<CONF
# Managed by secure_ssh_mostafa.sh on $(date -u)
# Hardened SSH settings
PermitRootLogin ${permit}
PubkeyAuthentication yes
PasswordAuthentication $( [[ "$key_only" == "yes" ]] && echo "no" || echo "yes" )
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 2
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 4
# Modern crypto (comment if clients are old)
# Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
$( [[ "$port" != "22" ]] && echo "Port ${port}" )
CONF
  ok "SSHD hardening drop-in written: $drop_file"

  echo -n "Testing sshd config... "
  sshd -t
  ok "OK"
  systemctl reload ssh || systemctl restart ssh
  ok "sshd reloaded."
}

# ===== Fail2Ban Strict Policy =====
setup_fail2ban(){
  ok "Installing/Configuring Fail2Ban (strict)…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban

  local jaild="/etc/fail2ban/jail.d"
  mkdir -p "$jaild"

  local ignore_ip
  ignore_ip="$(prompt "Enter trusted IP/CIDR to never ban (optional, space-separated)" "")"

  cat >"${jaild}/00-defaults.local" <<JAIL
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1${ignore_ip:+ $ignore_ip}
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
banaction = iptables-multiport

# Progressive bantime
bantime.increment = true
bantime.rndtime = 15m
bantime.factor = 1.8
bantime.maxtime = 48h
JAIL

  cat >"${jaild}/sshd.local" <<'JAIL'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 4
findtime = 10m
JAIL

  # Optional: Recidive for persistent offenders
  cat >"${jaild}/recidive.local" <<'JAIL'
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 7d
findtime = 1d
maxretry = 5
JAIL

  systemctl enable --now fail2ban
  systemctl restart fail2ban
  ok "Fail2Ban is active."
}

# ===== User Management =====
ensure_user_and_key(){
  local target_user="$1"
  local have_key="$2"   # "yes" if user already has authorized_keys and you want to keep
  local pub_key="$3"    # if empty and have_key != yes, we will prompt/paste

  if ! id -u "$target_user" &>/dev/null; then
    ok "Creating user: $target_user"
    useradd -m -s /bin/bash "$target_user"
  else
    ok "User exists: $target_user"
  fi

  local ssh_dir="/home/${target_user}/.ssh"
  local auth="${ssh_dir}/authorized_keys"
  install -d -m 700 -o "$target_user" -g "$target_user" "$ssh_dir"

  if [[ "$have_key" == "yes" && -s "$auth" ]]; then
    ok "Keeping existing authorized_keys for $target_user"
  else
    if [[ -z "$pub_key" ]]; then
      echo "Paste PUBLIC SSH KEY for ${target_user}, then ENTER + CTRL+D:"
      pub_key="$(</dev/stdin || true)"
      pub_key="${pub_key//[$'\r']}"
      [[ -z "$pub_key" ]] && die "Public key is empty."
    fi
    umask 077
    printf '%s\n' "$pub_key" > "$auth"
    chown "$target_user:$target_user" "$auth"
    chmod 600 "$auth"
    ok "authorized_keys installed for $target_user"
  fi
}

maybe_add_sudo(){
  local user="$1"
  if confirm "Add ${user} to sudo group?"; then
    usermod -aG sudo "$user"
    ok "Added $user to sudo."
  fi
}

# ===== Main =====
main(){
  require_root
  require_bins
  banner

  echo "$(bold 'This script will:')"
  echo " - Harden SSH (drop-in config, safe reload)"
  echo " - Configure strict Fail2Ban policies"
  echo " - Create or reuse a non-root user with SSH key"
  hr

  # Pick user mode
  local target_user=""
  local creator_mode="create"  # create|reuse
  local login_user="${SUDO_USER:-$(logname 2>/dev/null || true)}"
  [[ -z "$login_user" || "$login_user" == "root" ]] && login_user=""

  if [[ -n "$login_user" ]] && id -u "$login_user" &>/dev/null && [[ "$login_user" != "root" ]]; then
    echo "Detected current login user: $(bold "$login_user")"
    if confirm "Use current user '$login_user'?"; then
      target_user="$login_user"
      creator_mode="reuse"
    fi
  fi

  if [[ -z "$target_user" ]]; then
    target_user="$(prompt "Enter username to create/reuse" "devops")"
    if id -u "$target_user" &>/dev/null; then
      creator_mode="reuse"
    else
      creator_mode="create"
    fi
  fi

  # Port & policy prompts
  local ssh_port
  ssh_port="$(prompt "SSH port" "22")"
  local enforce_keys="no"
  confirm "Enforce key-only login (disable PasswordAuthentication)?" && enforce_keys="yes"
  local lock_root="no"
  confirm "Disable root SSH login NOW (PermitRootLogin no)?" && lock_root="yes"

  # Prepare user and key
  if [[ "$creator_mode" == "reuse" ]]; then
    local keep_existing="no"
    [[ -f "/home/${target_user}/.ssh/authorized_keys" ]] && confirm "Keep existing authorized_keys for ${target_user}?" && keep_existing="yes"
    ensure_user_and_key "$target_user" "$keep_existing" ""
  else
    ensure_user_and_key "$target_user" "no" ""
  fi
  maybe_add_sudo "$target_user"

  # SSH hardening
  write_sshd_dropin "$ssh_port" "$enforce_keys" "$lock_root"

  # UFW hint
  if command -v ufw &>/dev/null; then
    if [[ "$ssh_port" != "22" ]]; then
      warn "UFW detected. Run:"
      echo "  ufw allow ${ssh_port}/tcp"
      echo "  (After confirming new port works) ufw delete allow 22/tcp"
    else
      note "Ensure firewall allows 22/tcp"
    fi
  fi

  # Fail2Ban strict setup
  if confirm "Install & configure Fail2Ban with strict rules?"; then
    setup_fail2ban
  else
    warn "Skipped Fail2Ban configuration."
  fi

  hr
  ok "Done."
  echo "Next steps:"
  echo "  1) Keep this session open."
  echo "  2) From another terminal: ssh -p ${ssh_port} ${target_user}@<SERVER-IP>"
  echo "  3) Verify access, then you're safe to close."
  echo
  echo "Rollback quick tips:"
  echo "  - Remove drop-in: rm /etc/ssh/sshd_config.d/10-hardening.conf && systemctl reload ssh"
  echo "  - Temporarily allow root: echo 'PermitRootLogin yes' >/etc/ssh/sshd_config.d/99-temp-root.conf && systemctl reload ssh"
}

main "$@"
