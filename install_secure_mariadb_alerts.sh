#!/bin/bash
set -Eeuo pipefail

################################################################################
# WooCommerce MariaDB Setup Script (Hardened + Optimized + Backups + Monitoring)
# - Secure MariaDB (remove test/anonymous, lock remote root, set root password)
# - Create WooCommerce DB + user (local + optional remote IP)
# - Performance tuning based on RAM
# - UFW rule (optional) for remote IP on 3306
# - Daily backups (gzip + retention) without embedding passwords in scripts
# - Weekly mysqltuner email report
#
# Notes / Improvements vs original:
# - Installs MariaDB first, then secures it correctly.
# - Uses /root/.my.cnf for root credentials (cron-safe, no password in scripts).
# - Idempotent where possible (won’t duplicate cron jobs / configs).
# - Safer config edits (does not blindly sed unknown lines).
# - Optional: enable remote access and firewall opening explicitly.
################################################################################

#-----------------------------#
# Root check
#-----------------------------#
if [[ ${EUID} -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

#-----------------------------#
# Logging
#-----------------------------#
LOG_FILE="/var/log/mariadb_woocommerce_setup.log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

trap 'echo "[ERROR] Line $LINENO failed. See: $LOG_FILE" >&2' ERR

#-----------------------------#
# Helpers
#-----------------------------#
have_cmd() { command -v "$1" >/dev/null 2>&1; }

set_owner() {
  local target="$1"
  if id "mysql" &>/dev/null; then
    chown mysql:mysql "$target" || true
  else
    chown root:root "$target" || true
  fi
}

generate_random_string() {
  local length="${1:-16}"
  tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c "$length" || true
}

prompt() {
  local __var="$1"
  local msg="$2"
  local def="${3:-}"
  local secret="${4:-no}"
  local input=""

  if [[ "$secret" == "yes" ]]; then
    read -r -s -p "$msg${def:+ [default: $def]}: " input
    echo
  else
    read -r -p "$msg${def:+ [default: $def]}: " input
  fi

  if [[ -z "$input" ]]; then
    input="$def"
  fi

  printf -v "$__var" '%s' "$input"
}

validate_email() {
  local email="$1"
  [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

validate_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  # Basic range validation (0-255)
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

#-----------------------------#
# Defaults
#-----------------------------#
DEFAULT_DB_NAME="woocommerce_$(generate_random_string 8)"
DEFAULT_DB_USER="wc_$(generate_random_string 6)"
DEFAULT_DB_PASSWORD="$(generate_random_string 24)"
DEFAULT_DB_ROOT_PASSWORD="$(generate_random_string 32)"
DEFAULT_BACKUP_DIR="/var/backups/mariadb"
DEFAULT_BACKUP_HOUR="2"
DEFAULT_BACKUP_MINUTE="0"
DEFAULT_RETENTION_DAYS="14"

#-----------------------------#
# Collect input
#-----------------------------#
echo "Welcome to the WooCommerce MariaDB Setup Script!"
echo "This will install and secure MariaDB, create WooCommerce DB/user, configure tuning,"
echo "enable automated backups + retention, and schedule mysqltuner email reports."
echo

while true; do
  prompt ALERT_EMAIL "Alerts email" "admin@example.com" "no"
  if validate_email "$ALERT_EMAIL"; then
    break
  fi
  echo "Invalid email address. Try again."
done

prompt DB_ROOT_PASSWORD "MariaDB root password" "$DEFAULT_DB_ROOT_PASSWORD" "yes"
prompt DB_NAME          "WooCommerce database name" "$DEFAULT_DB_NAME" "no"
prompt DB_USER          "WooCommerce database username" "$DEFAULT_DB_USER" "no"
prompt DB_PASSWORD      "WooCommerce database user password" "$DEFAULT_DB_PASSWORD" "yes"

# Remote access is optional (safer default)
prompt ENABLE_REMOTE "Enable remote DB access for one IP?" "no" "no"
ENABLE_REMOTE="${ENABLE_REMOTE,,}"  # to lower
REMOTE_IP=""
if [[ "$ENABLE_REMOTE" == "yes" ]]; then
  while true; do
    prompt REMOTE_IP "Remote IPv4 allowed to connect to MariaDB (single IP)" "" "no"
    if [[ -n "$REMOTE_IP" ]] && validate_ipv4 "$REMOTE_IP"; then
      break
    fi
    echo "Invalid IP. Try again."
  done
fi

prompt BACKUP_DIR "Backup directory" "$DEFAULT_BACKUP_DIR" "no"
prompt BACKUP_HOUR "Daily backup hour (0-23)" "$DEFAULT_BACKUP_HOUR" "no"
prompt BACKUP_MINUTE "Daily backup minute (0-59)" "$DEFAULT_BACKUP_MINUTE" "no"
prompt RETENTION_DAYS "Keep backups for N days" "$DEFAULT_RETENTION_DAYS" "no"

# Optional Google Drive upload via rclone
prompt ENABLE_GDRIVE_UPLOAD "Enable auto-upload of backups to Google Drive via rclone?" "no" "no"
ENABLE_GDRIVE_UPLOAD="${ENABLE_GDRIVE_UPLOAD,,}"

# Optional firewall rule via UFW (only if remote is enabled)
ENABLE_UFW="no"
if [[ "$ENABLE_REMOTE" == "yes" ]]; then
  prompt ENABLE_UFW "Configure UFW to allow ${REMOTE_IP} -> 3306?" "yes" "no"
  ENABLE_UFW="${ENABLE_UFW,,}"
fi

#-----------------------------#
# Determine resources
#-----------------------------#
TOTAL_RAM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
CPU_CORES="$(nproc 2>/dev/null || echo 1)"

# Buffer pool sizing (70% of RAM, capped reasonably for small systems if needed)
# If RAM is tiny, avoid huge allocation.
TOTAL_RAM_MB=$(( TOTAL_RAM_KB / 1024 ))
if (( TOTAL_RAM_MB <= 1024 )); then
  INNODB_BUFFER_POOL_MB=$(( TOTAL_RAM_MB * 50 / 100 ))
else
  INNODB_BUFFER_POOL_MB=$(( TOTAL_RAM_MB * 70 / 100 ))
fi
# Safety floor/ceiling
if (( INNODB_BUFFER_POOL_MB < 256 )); then INNODB_BUFFER_POOL_MB=256; fi
MAX_CONNECTIONS="300"

echo
echo "Detected resources: ${TOTAL_RAM_MB} MB RAM, ${CPU_CORES} CPU cores"
echo "Planned innodb_buffer_pool_size: ${INNODB_BUFFER_POOL_MB}M"
echo

#-----------------------------#
# Prepare backup dir
#-----------------------------#
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
set_owner "$BACKUP_DIR"

#-----------------------------#
# OS prerequisites
#-----------------------------#
export DEBIAN_FRONTEND=noninteractive

echo "Updating apt metadata..."
apt-get update -y

echo "Fixing broken packages (if any)..."
apt-get -f install -y || true

echo "Installing required packages..."
apt-get install -y \
  mariadb-server mariadb-client \
  cron gzip \
  sendmail mailutils \
  mysqltuner \
  ufw \
  ca-certificates curl

#-----------------------------#
# Start/enable MariaDB
#-----------------------------#
systemctl enable --now mariadb

#-----------------------------#
# Secure MariaDB & set root password
# Strategy:
# - Many distros use unix_socket auth for root (no password). We'll:
#   1) Try socket login first.
#   2) Set a root password and keep root@localhost accessible.
#   3) Remove anonymous/test DB, disallow remote root.
# - Then write /root/.my.cnf for cron-safe root access without inline passwords.
#-----------------------------#
echo "Securing MariaDB..."

mysql_exec_socket() {
  mysql --protocol=socket -uroot -e "$1"
}

mysql_exec_pw() {
  mysql -uroot -p"${DB_ROOT_PASSWORD}" -e "$1"
}

# Determine if socket login works
if mysql_exec_socket "SELECT 1;" >/dev/null 2>&1; then
  echo "Root socket authentication detected; applying hardening via socket login..."
  mysql_exec_socket "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';" || true
  # If root is using unix_socket plugin, force password auth (best-effort; varies by distro/MariaDB version)
  mysql_exec_socket "UPDATE mysql.user SET plugin='' WHERE User='root' AND Host='localhost';" || true
  mysql_exec_socket "FLUSH PRIVILEGES;"
else
  echo "Root socket login not available; attempting password-based hardening..."
  # If root already has a password (unknown), this may fail. We continue and rely on manual fix if needed.
  mysql_exec_pw "SELECT 1;" >/dev/null 2>&1 || {
    echo "[WARN] Could not authenticate as root using provided password. If MariaDB root auth differs on this host,"
    echo "       update the root credentials and re-run, or adjust root auth method manually."
    exit 1
  }
fi

# Now use password-based commands (root password should be in place)
mysql_exec_pw "DELETE FROM mysql.user WHERE User='';"
mysql_exec_pw "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');"
mysql_exec_pw "DROP DATABASE IF EXISTS test;"
mysql_exec_pw "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysql_exec_pw "FLUSH PRIVILEGES;"

# Write root credentials for cron jobs (safer than embedding password in scripts)
ROOT_CNF="/root/.my.cnf"
cat > "$ROOT_CNF" <<EOF
[client]
user=root
password=${DB_ROOT_PASSWORD}
host=localhost
EOF
chmod 600 "$ROOT_CNF"

#-----------------------------#
# Create WooCommerce DB + user
#-----------------------------#
echo "Creating WooCommerce database and user..."

mysql_exec_pw "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql_exec_pw "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql_exec_pw "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"

if [[ "$ENABLE_REMOTE" == "yes" ]]; then
  mysql_exec_pw "CREATE USER IF NOT EXISTS '${DB_USER}'@'${REMOTE_IP}' IDENTIFIED BY '${DB_PASSWORD}';"
  mysql_exec_pw "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'${REMOTE_IP}';"
fi

mysql_exec_pw "FLUSH PRIVILEGES;"

#-----------------------------#
# Configure bind-address
# - If remote is enabled, bind to 0.0.0.0 (or private IP). Safer is private IP,
#   but varies by network. We’ll default to 0.0.0.0 ONLY when remote enabled.
# - If remote is not enabled, keep localhost.
#-----------------------------#
SERVER_CNF="/etc/mysql/mariadb.conf.d/50-server.cnf"

echo "Configuring MariaDB bind-address..."
if [[ -f "$SERVER_CNF" ]]; then
  if [[ "$ENABLE_REMOTE" == "yes" ]]; then
    # Listen on all interfaces but restrict by grants + firewall
    if grep -qE '^\s*bind-address\s*=' "$SERVER_CNF"; then
      sed -i 's/^\s*bind-address\s*=.*/bind-address = 0.0.0.0/' "$SERVER_CNF"
    else
      echo "bind-address = 0.0.0.0" >> "$SERVER_CNF"
    fi
  else
    if grep -qE '^\s*bind-address\s*=' "$SERVER_CNF"; then
      sed -i 's/^\s*bind-address\s*=.*/bind-address = 127.0.0.1/' "$SERVER_CNF"
    else
      echo "bind-address = 127.0.0.1" >> "$SERVER_CNF"
    fi
  fi
else
  echo "[WARN] Could not find $SERVER_CNF; skipping bind-address update."
fi

#-----------------------------#
# Performance config
# - Avoid query_cache on modern MariaDB setups if not desired; keep it off.
# - Add slow log and sensible InnoDB tuning.
#-----------------------------#
echo "Writing performance configuration..."

mkdir -p /var/log/mysql
chmod 750 /var/log/mysql
set_owner /var/log/mysql

OPT_CNF="/etc/mysql/mariadb.conf.d/99-woocommerce-optimized.cnf"
cat > "$OPT_CNF" <<EOF
[mysqld]
# --- Core performance (WooCommerce-friendly) ---
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL_MB}M
innodb_buffer_pool_instances = ${CPU_CORES}
innodb_log_file_size = 512M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
max_connections = ${MAX_CONNECTIONS}

# --- Character set ---
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# --- Slow query logging ---
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2

# --- Binary logs (optional; can be heavy on disk). Comment out if not needed.
# log_bin = /var/log/mysql/mysql-bin.log
# binlog_expire_logs_seconds = 604800

# --- Disable query cache (generally not recommended for modern workloads)
query_cache_type = 0
query_cache_size = 0
EOF

chmod 640 "$OPT_CNF"
set_owner "$OPT_CNF"

#-----------------------------#
# Restart MariaDB
#-----------------------------#
echo "Restarting MariaDB..."
systemctl restart mariadb
systemctl is-active --quiet mariadb

#-----------------------------#
# Firewall (optional)
#-----------------------------#
if [[ "$ENABLE_REMOTE" == "yes" && "$ENABLE_UFW" == "yes" ]]; then
  echo "Configuring UFW rule for ${REMOTE_IP} -> 3306..."
  # Ensure ufw enabled (best-effort; do not break servers unexpectedly)
  if ufw status | grep -qi "inactive"; then
    echo "[INFO] UFW is inactive. Enabling UFW..."
    ufw --force enable
  fi
  ufw allow from "$REMOTE_IP" to any port 3306 proto tcp
fi

#-----------------------------#
# Backups: daily cron + retention
# - Use /root/.my.cnf so no password in script.
# - Add basic integrity check (gzip + size).
#-----------------------------#
echo "Setting up automated backups..."

BACKUP_SCRIPT="/usr/local/bin/mariadb_woocommerce_backup.sh"
cat > "$BACKUP_SCRIPT" <<EOF
#!/bin/bash
set -Eeuo pipefail

DB_NAME="${DB_NAME}"
BACKUP_DIR="${BACKUP_DIR}"
RETENTION_DAYS="${RETENTION_DAYS}"

mkdir -p "\$BACKUP_DIR"
chmod 700 "\$BACKUP_DIR"

TS=\$(date +%F_%H-%M-%S)
OUT="\$BACKUP_DIR/\${DB_NAME}_\${TS}.sql.gz"
TMP="\$BACKUP_DIR/.tmp_\${DB_NAME}_\${TS}.sql.gz"

# Dump + compress
mysqldump --defaults-file=/root/.my.cnf --single-transaction --quick --routines --events "\$DB_NAME" | gzip -1 > "\$TMP"

# Basic validation
if [[ ! -s "\$TMP" ]]; then
  echo "[ERROR] Backup output is empty: \$TMP" >&2
  exit 1
fi
gzip -t "\$TMP"

mv "\$TMP" "\$OUT"
echo "[OK] Backup created: \$OUT"

# Retention
find "\$BACKUP_DIR" -type f -name "\${DB_NAME}_*.sql.gz" -mtime +"\$RETENTION_DAYS" -print -delete || true

# Optional Google Drive upload
ENABLE_GDRIVE_UPLOAD="${ENABLE_GDRIVE_UPLOAD}"
if [[ "\${ENABLE_GDRIVE_UPLOAD,,}" == "yes" ]]; then
  if command -v rclone >/dev/null 2>&1; then
    rclone copy "\$OUT" remote:backups/ --create-empty-src-dirs
    echo "[OK] Uploaded to Google Drive via rclone."
  else
    echo "[WARN] rclone not found; skipping upload." >&2
  fi
fi
EOF

chmod 700 "$BACKUP_SCRIPT"

# Create cron job
CRON_FILE="/etc/cron.d/mariadb_woocommerce_backup"
printf "%s %s * * * root %s\n" "$BACKUP_MINUTE" "$BACKUP_HOUR" "$BACKUP_SCRIPT" > "$CRON_FILE"
chmod 600 "$CRON_FILE"

#-----------------------------#
# Google Drive via rclone (optional)
#-----------------------------#
if [[ "$ENABLE_GDRIVE_UPLOAD" == "yes" ]]; then
  echo "Google Drive upload enabled."
  if ! have_cmd rclone; then
    echo "Installing rclone..."
    curl -fsSL https://rclone.org/install.sh | bash
  fi
  echo "Launching rclone config (interactive). Configure a remote named: remote"
  rclone config
fi

#-----------------------------#
# Weekly mysqltuner report
#-----------------------------#
echo "Setting up weekly monitoring with mysqltuner..."

TUNER_SCRIPT="/etc/cron.weekly/mariadb_tuner_report"
cat > "$TUNER_SCRIPT" <<EOF
#!/bin/bash
set -Eeuo pipefail
/usr/bin/mysqltuner --defaults-file=/root/.my.cnf --silent | mail -s "MariaDB Tuner Report" "${ALERT_EMAIL}"
EOF
chmod 700 "$TUNER_SCRIPT"

#-----------------------------#
# Final Summary
#-----------------------------#
echo
echo "MariaDB setup for WooCommerce is complete."
echo "Server resources: ${TOTAL_RAM_MB} MB RAM, ${CPU_CORES} CPU cores."
echo "Database created: ${DB_NAME}"
echo "User created:     ${DB_USER}"
echo "Remote access:    ${ENABLE_REMOTE}${REMOTE_IP:+ (allowed IP: ${REMOTE_IP})}"
echo "Backups:          Daily at ${BACKUP_HOUR}:${BACKUP_MINUTE} (retention: ${RETENTION_DAYS} days) -> ${BACKUP_DIR}"
echo "mysqltuner:       Weekly report -> ${ALERT_EMAIL}"
echo "Log file:         ${LOG_FILE}"
echo
echo "Generated/used credentials (store them securely):"
echo "  - DB Name:            ${DB_NAME}"
echo "  - DB User:            ${DB_USER}"
echo "  - DB User Password:   ${DB_PASSWORD}"
echo "  - MariaDB Root Pass:  ${DB_ROOT_PASSWORD}"
echo
echo "Root credentials saved for cron at: /root/.my.cnf (600 permissions)."
