#!/usr/bin/env bash
# SSH-Secure.sh — Secure SSH Access By Mostafa Mohamed
# Harden SSH, provision user keys (explicit paste + CTRL+D), and set strict Fail2Ban policies safely.

set -Eeuo pipefail
IFS=$'\n\t'

# ========= UI =========
bold(){ printf '\e[1m%s\e[0m\n' "$*"; }
ok(){ echo -e "✅ $*"; }
warn(){ echo -e "⚠️  $*"; }
err(){ echo -e "❌ $*" >&2; }
hr(){ printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '─'; }
banner(){
  clear
  echo
  echo -e "╔══════════════════════════════════════════════════════════════╗"
  printf  "║  %-58s ║\n" "Secure SSH Access"
  printf  "║  %-58s ║\n" "By Mostafa Mohamed"
  echo -e "╚══════════════════════════════════════════════════════════════╝"
  echo
}
die(){ err "$*"; exit 1; }
trap 'err "Something went wrong. Check messages above."' ERR

# ========= Helpers =========
require_root(){ [[ $EUID -eq 0 ]] || die "Run as root (use sudo)."; }
need_bins(){ for b in "$@"; do command -v "$b" >/dev/null || die "Missing: $b"; done; }

prompt(){ local m="$1" d="${2:-}"; local a; read -r -p "$m ${d:+[$d]}: " a < /dev/tty; echo "${a:-$d}"; }
confirm(){ local m="$1" a; while true; do read -r -p "$m [y/n]: " a < /dev/tty; case "$a" in [Yy]*) return 0;; [Nn]*) return 1;; esac; done; }

# Find homedir even if not /home/<user>
user_home(){
  local u="$1"
  local h
  h="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$h" ]] || die "Cannot determine home for $u"
  echo "$h"
}

# ========= Capture pubkey from keyboard (paste + CTRL+D) =========
capture_pubkey(){
  local user="$1"
  local tmp
  tmp="$(mktemp)"
  echo "Paste PUBLIC SSH KEY for ${user}, then press ENTER and CTRL+D:"
  # Force-read from controlling terminal so it ALWAYS waits for your paste
  cat > "$tmp" < /dev/tty
  # Normalize CR from PuTTY/Windows pastes
  tr -d '\r' < "$tmp" > "${tmp}.n"
  mv -f "${tmp}.n" "$tmp"

  # Basic sanity check
  if ! grep -qE '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) ' "$tmp"; then
    warn "The pasted text does not look like a standard OpenSSH public key. Continuing anyway."
  fi

  # Ensure not empty
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    die "Public key is empty."
  fi
  echo "$tmp"
}

# ========= SSHD drop-in =========
write_sshd_dropin(){
  local port="$1" key_only="$2" lock_root="$3"
  local drop_dir="/etc/ssh/sshd_config.d"
  local drop_file="${drop_dir}/10-hardening.conf"
  mkdir -p "$drop_dir"

  local permit="prohibit-password"
  [[ "$lock_root" == "yes" ]] && permit="no"

  cat >"$drop_file" <<CONF
# Managed by SSH-Secure.sh on $(date -u)
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
# Uncomment if all clients are modern:
# Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
# MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
$( [[ "$port" != "22" ]] && echo "Port ${port}" )
CONF

  echo -n "Testing sshd config... "
  sshd -t
  ok "OK"
  systemctl reload ssh || systemctl restart ssh
  ok "sshd reloaded"
}

# ========= Fail2Ban =========
setup_fail2ban(){
  ok "Installing & configuring Fail2Ban (strict)…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban

  local jaild="/etc/fail2ban/jail.d"
  mkdir -p "$jaild"

  local ignore_ip
  ignore_ip="$(prompt "Trusted IP/CIDR to whitelist (space-separated, optional)" "")"

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
  ok "Fail2Ban active"
}

# ========= Keys management (always interactively paste) =========
install_key_for_user(){
  local user="$1"
  local h auth mode="replace"
  h="$(user_home "$user")"
  install -d -m 700 -o "$user" -g "$user" "$h/.ssh"
  auth="$h/.ssh/authorized_keys"

  if [[ -s "$auth" ]]; then
    echo "authorized_keys exists for $user."
    while true; do
      read -r -p "Choose what to do: [R]eplace / [A]ppend / [K]eep existing: " ans < /dev/tty
      case "${ans,,}" in
        r|replace) mode="replace"; break;;
        a|append)  mode="append";  break;;
        k|keep)    mode="keep";    break;;
      esac
    done
  fi

  local tmp=""
  if [[ "$mode" != "keep" ]]; then
    tmp="$(capture_pubkey "$user")"
  fi

  umask 077
  case "$mode" in
    replace)
      cat "$tmp" > "$auth"
      ;;
    append)
      printf '\n' >> "$auth" 2>/dev/null || true
      cat "$tmp" >> "$auth"
      ;;
    keep)
      ok "Keeping existing authorized_keys for $user"
      ;;
  esac
  [[ -n "$tmp" && -f "$tmp" ]] && rm -f "$tmp"

  chown "$user:$user" "$auth"
  chmod 600 "$auth"
  ok "authorized_keys ready for $user (mode: $mode)"
}

# ========= User flow =========
ensure_user(){
  local target="$1"
  if id -u "$target" &>/dev/null; then
    ok "User exists: $target"
  else
    ok "Creating user: $target"
    useradd -m -s /bin/bash "$target"
  fi
}

maybe_add_sudo(){
  local user="$1"
  if confirm "Add ${user} to sudo group?"; then
    usermod -aG sudo "$user"
    ok "Added $user to sudo"
  fi
}

# ========= Main =========
main(){
  require_root
  need_bins awk grep cut getent id useradd usermod install chmod chown systemctl sshd cat tr

  banner
  bold "This will:"
  echo " - Create/reuse non-root user and set SSH public key (paste + CTRL+D)"
  echo " - Harden SSH via drop-in config (safe reload)"
  echo " - Configure strict Fail2Ban rules (optional)"
  hr

  # Pick user: current or new
  local login_user="${SUDO_USER:-$(logname 2>/dev/null || true)}"
  local target_user="" choice
  if [[ -n "$login_user" && "$login_user" != "root" && $(id -u "$login_user" 2>/dev/null || echo "") ]]; then
    echo "Detected current user: $(bold "$login_user")"
    if confirm "Use current user '$login_user'?"; then
      target_user="$login_user"
    fi
  fi
  if [[ -z "$target_user" ]]; then
    choice="$(prompt "Enter username to create/reuse" "devops")"
    target_user="$choice"
  fi

  ensure_user "$target_user"
  install_key_for_user "$target_user"
  maybe_add_sudo "$target_user"

  # SSH policy choices
  local ssh_port key_only="no" lock_root="no"
  ssh_port="$(prompt "SSH port" "22")"
  confirm "Enforce key-only login (disable PasswordAuthentication)?" && key_only="yes"
  confirm "Disable root SSH login NOW (PermitRootLogin no)?" && lock_root="yes"

  write_sshd_dropin "$ssh_port" "$key_only" "$lock_root"

  # UFW hints
  if command -v ufw &>/dev/null; then
    if [[ "$ssh_port" != "22" ]]; then
      warn "UFW detected. Ensure new port allowed:"
      echo "  ufw allow ${ssh_port}/tcp"
      echo "  (After confirming) ufw delete allow 22/tcp"
    else
      echo "If UFW is active, ensure: ufw allow 22/tcp"
    fi
  fi

  # Fail2Ban
  if confirm "Install & configure Fail2Ban with strict rules?"; then
    setup_fail2ban
  else
    warn "Skipped Fail2Ban configuration."
  fi

  hr
  ok "All done."
  echo "Next:"
  echo "  1) KEEP THIS SESSION OPEN."
  echo "  2) From another terminal: ssh -p ${ssh_port} ${target_user}@<SERVER-IP>"
  echo "  3) Verify access before closing."
  echo
  echo "Quick rollback:"
  echo "  rm /etc/ssh/sshd_config.d/10-hardening.conf && systemctl reload ssh"
  echo "  # temporarily allow root if needed:"
  echo "  echo 'PermitRootLogin yes' >/etc/ssh/sshd_config.d/99-temp-root.conf && systemctl reload ssh"
}

main "$@"
