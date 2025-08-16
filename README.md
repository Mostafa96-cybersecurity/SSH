# SSH-Secure.sh — Secure SSH Access By Mostafa Mohamed

This script provides a **secure, automated way** to harden SSH access on your server.
It simplifies user provisioning, enforces strong SSH configurations, and protects against brute-force attacks using **Fail2Ban**.

---

## ✨ Features

* **Beautiful Banner**: Starts with a clear branded banner for easy identification.
* **User Choice**:

  * Use the **current non-root user** (if available), OR
  * Create a **new dedicated SSH user**.
* **SSH Key Authentication**:

  * Prompts you to paste a public key (or reuse existing keys).
  * Configures `~/.ssh/authorized_keys` securely.
* **SSH Hardening**:

  * Creates a drop-in file under `/etc/ssh/sshd_config.d/` (no risk of breaking the main config).
  * Options to:

    * Change the SSH port.
    * Disable password login (enforce key-only).
    * Disable root SSH login.
  * Secure defaults:

    * `MaxAuthTries=2`
    * `LoginGraceTime=20`
    * No X11 forwarding.
* **Fail2Ban Strict Rules**:

  * Auto-installs Fail2Ban if missing.
  * Strict defaults with **incremental bantime** (1h → 48h).
  * Recidive jail enabled (persistent offenders banned for 7 days).
  * Supports whitelisting trusted IPs.
* **Firewall Awareness**:

  * Detects `ufw` and gives hints to open the new SSH port.
* **Safe Reloads**:

  * Always tests SSH configuration with `sshd -t`.
  * Uses `systemctl reload ssh` instead of hard restart (to avoid locking you out).
* **Rollback Ready**:

  * Clear instructions to revert changes quickly if needed.

---

## ⚙️ Requirements

* OS: Ubuntu / Debian (systemd-based).
* Root privileges (`sudo`).
* Installed packages: `openssh-server`, `fail2ban` (auto-installed if missing).

---

## 🚀 Usage

1. Save the script as:

   ```bash
   SSH-Secure.sh
   ```
2. Make it executable:

   ```bash
   chmod +x SSH-Secure.sh
   ```
3. Run as root:

   ```bash
   sudo ./SSH-Secure.sh
   ```

---

## 📝 What Happens

1. Shows banner:

   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║  Secure SSH Access                                           ║
   ║  By Mostafa Mohamed                                          ║
   ╚══════════════════════════════════════════════════════════════╝
   ```
2. Asks if you want to use your current user or create a new one.
3. Prompts for a public SSH key if needed.
4. Configures SSH hardening via drop-in file:

   * `/etc/ssh/sshd_config.d/10-hardening.conf`
5. Optionally installs and configures **Fail2Ban** with strict rules.
6. Reloads SSH safely and gives rollback instructions.

---

## 🔐 Rollback

If you lock yourself out or need to revert:

* **Remove drop-in config**:

  ```bash
  rm /etc/ssh/sshd_config.d/10-hardening.conf
  systemctl reload ssh
  ```
* **Re-enable root login temporarily**:

  ```bash
  echo "PermitRootLogin yes" >/etc/ssh/sshd_config.d/99-temp-root.conf
  systemctl reload ssh
  ```

---

## ⚠️ Important Notes

* Always keep your current SSH session open until you **successfully test the new user**.
* If you change the port, make sure your firewall allows it (e.g., `ufw allow <port>/tcp`).
* Whitelist your own IP in Fail2Ban to avoid accidental bans.

---

## ✅ Example Run

```bash
sudo ./SSH-Secure.sh
# → Use current user? [y/n]: y
# → SSH port [22]:
# → Enforce key-only login? [y/n]: y
# → Disable root login? [y/n]: y
# → Install Fail2Ban with strict rules? [y/n]: y
```

---

📌 With this script, you get a **ready-to-use hardened SSH setup** that combines
**secure user management, strict login policies, and brute-force protection**.
