#!/bin/bash
# Services Hardening Script
# Module: Services
# Supports: scan, fix, rollback modes

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/services"
ROLLBACK_SCRIPT="$SCRIPT_DIR/../rollback_services.bash"
TOPIC="Services"
MODULE_NAME="Services"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fixed() {
    echo -e "${GREEN}[FIXED]${NC} $1"
}

log_manual() {
    echo -e "${BLUE}[MANUAL]${NC} $1"
}

# =========================
# Database Initialization
# =========================
init_database() {
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    # Create scan_results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            expected_value TEXT NOT NULL,
            current_value TEXT NOT NULL,
            status TEXT NOT NULL,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(module_name, policy_id)
        );
    ''')
    
    # Create fix_history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fix_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            expected_value TEXT NOT NULL,
            original_value TEXT NOT NULL,
            current_value TEXT NOT NULL,
            status TEXT NOT NULL,
            fix_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            rollback_executed TEXT DEFAULT 'NO',
            UNIQUE(module_name, policy_id)
        );
    ''')
    
    conn.commit()
    conn.close()
    print('Database initialized successfully')
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# =========================
# Standard Output Function
# =========================
print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"
    
    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    echo "Status         : $status"
    echo "=============================================="
}

# =========================
# Save to scan_results table
# =========================
save_scan_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local current_value="$4"
    local status="$5"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO scan_results 
        (module_name, policy_id, policy_name, expected_value, current_value, status, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ''', ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected_value''', '''$current_value''', '$status'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# =========================
# Save to fix_history table
# =========================
save_fix_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected_value="$3"
    local original_value="$4"
    local current_value="$5"
    local status="$6"
    
    python3 -c "
import sqlite3
import sys

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO fix_history 
        (module_name, policy_id, policy_name, expected_value, original_value, current_value, status, fix_timestamp, rollback_executed)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), 'NO')
    ''', ('$MODULE_NAME', '$policy_id', '''$policy_name''', '''$expected_value''', '''$original_value''', '''$current_value''', '$status'))
    
    conn.commit()
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# =========================
# Get scan result from database
# =========================
get_scan_result() {
    local policy_id="$1"
    python3 -c "
import sqlite3
import sys
import json

try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT current_value, status 
        FROM scan_results 
        WHERE module_name=? AND policy_id=?
    ''', ('$MODULE_NAME', '$policy_id'))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        print(json.dumps({'current_value': result[0], 'status': result[1]}))
    else:
        print(json.dumps({'current_value': '', 'status': ''}))
        
except Exception as e:
    print(json.dumps({'current_value': '', 'status': ''}), file=sys.stderr)
" 2>/dev/null
}

# =========================
# Service Status Checker
# =========================
is_disabled() {
    local state
    state=$(systemctl is-enabled "$1" 2>/dev/null)
    case "$state" in
        disabled|masked|static|indirect|not-found)
            return 0 ;;
        *)  return 1 ;;
    esac
}

disable_service() {
    systemctl stop "$1" 2>/dev/null
    systemctl disable "$1" 2>/dev/null
    systemctl mask "$1" 2>/dev/null
}

enable_service() {
    systemctl unmask "$1" 2>/dev/null
    systemctl enable "$1" 2>/dev/null
    systemctl start "$1" 2>/dev/null
}

# =========================
# Service Hardening Functions
# =========================
check_service() {
    local policy_id="$1"
    local policy_name="$2"
    local service="$3"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="disabled/masked"
        local current="unknown"
        
        if is_disabled "$service"; then
            current=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current=$(systemctl is-enabled "$service" 2>/dev/null || echo "enabled")
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            # No scan data, get current state
            original_value=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
        fi
        
        # Backup service status
        local backup_file="$BACKUP_DIR/${service}_status.txt"
        echo "original_state=$original_value" > "$backup_file"
        echo "timestamp=$(date +%Y%m%d_%H%M%S)" >> "$backup_file"
        
        disable_service "$service"
        
        local current_value=$(systemctl is-enabled "$service" 2>/dev/null || echo "masked")
        local expected="disabled/masked"
        local status="PASS"
        
        log_fixed "$policy_name"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rollback for $service will be handled by rollback script"
    fi
}

check_package() {
    local policy_id="$1"
    local policy_name="$2"
    local package="$3"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="not installed"
        local current="unknown"
        
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package"; then
            current="installed"
            ((FAILED_CHECKS++))
        else
            current="not installed"
            status="PASS"
            ((PASSED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            # No scan data, check current state
            if dpkg -l 2>/dev/null | grep -q "^ii.*$package"; then
                original_value="installed"
            else
                original_value="not installed"
            fi
        fi
        
        if [ "$original_value" = "installed" ]; then
            # Backup package list
            local backup_file="$BACKUP_DIR/${package}_backup.txt"
            dpkg -l "$package" 2>/dev/null > "$backup_file"
            
            apt remove -y "$package" >/dev/null 2>&1
            
            local current_value="not installed"
            local expected="not installed"
            local status="PASS"
            
            log_fixed "$policy_name"
            save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
            ((FIXED_CHECKS++))
        else
            log_pass "$package already not installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rollback for $package will be handled by rollback script"
    fi
}

# =========================
# Server Services Checks
# =========================
check_server_services() {
    log_info "=== 3.a Server Services ==="
    
    check_service "SRV-3.a.i" "Ensure autofs services are not in use" "autofs"
    check_service "SRV-3.a.ii" "Ensure avahi daemon services are not in use" "avahi-daemon"
    check_service "SRV-3.a.iii" "Ensure dhcp server services are not in use" "isc-dhcp-server"
    check_service "SRV-3.a.iv" "Ensure dns server services are not in use" "bind9"
    check_service "SRV-3.a.v" "Ensure dnsmasq services are not in use" "dnsmasq"
    check_service "SRV-3.a.vi" "Ensure ftp server services are not in use" "vsftpd"
    check_service "SRV-3.a.vii" "Ensure ldap server services are not in use" "slapd"
    check_service "SRV-3.a.viii" "Ensure message access server services are not in use" "dovecot"
    check_service "SRV-3.a.ix" "Ensure network file system services are not in use" "nfs-kernel-server"
    check_service "SRV-3.a.x" "Ensure nis server services are not in use" "nis"
    check_service "SRV-3.a.xi" "Ensure print server services are not in use" "cups"
    check_service "SRV-3.a.xii" "Ensure rpcbind services are not in use" "rpcbind"
    check_service "SRV-3.a.xiii" "Ensure rsync services are not in use" "rsync"
    check_service "SRV-3.a.xiv" "Ensure samba file server services are not in use" "smbd"
    check_service "SRV-3.a.xv" "Ensure snmp services are not in use" "snmpd"
    check_service "SRV-3.a.xvi" "Ensure tftp server services are not in use" "tftpd-hpa"
    check_service "SRV-3.a.xvii" "Ensure web proxy server services are not in use" "squid"
    check_service "SRV-3.a.xviii" "Ensure web server services are not in use" "apache2"
    check_service "SRV-3.a.xix" "Ensure xinetd services are not in use" "xinetd"
    check_service "SRV-3.a.xx" "Ensure X window server services are not in use" "gdm"
}

# =========================
# Client Services Checks
# =========================
check_client_services() {
    log_info "=== 3.b Client Services ==="
    
    check_package "SRV-3.b.i" "Ensure NIS Client is not installed" "nis"
    check_package "SRV-3.b.ii" "Ensure rsh client is not installed" "rsh-client"
    check_package "SRV-3.b.iii" "Ensure talk client is not installed" "talk"
    check_package "SRV-3.b.iv" "Ensure telnet client is not installed" "telnet"
    check_package "SRV-3.b.v" "Ensure ldap client is not installed" "ldap-utils"
    check_package "SRV-3.b.vi" "Ensure ftp client is not installed" "ftp"
}

# =========================
# Time Synchronization
# =========================
check_time_sync() {
    local policy_id="SRV-3.c"
    local policy_name="Ensure time synchronization is in use"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="chrony active and enabled"
        local current="unknown"
        
        if systemctl is-active chrony >/dev/null 2>&1 && systemctl is-enabled chrony >/dev/null 2>&1; then
            current="chrony active and enabled"
            status="PASS"
            ((PASSED_CHECKS++))
        elif systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
            current="systemd-timesyncd active"
            ((FAILED_CHECKS++))
        else
            current="no time sync configured"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            if systemctl is-active chrony >/dev/null 2>&1; then
                original_value="chrony active"
            elif systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
                original_value="systemd-timesyncd active"
            else
                original_value="no time sync"
            fi
        fi
        
        # Backup time sync config
        if [ -f /etc/systemd/timesyncd.conf ]; then
            cp /etc/systemd/timesyncd.conf "$BACKUP_DIR/timesyncd.conf.$(date +%Y%m%d_%H%M%S)"
        fi
        
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        systemctl mask systemd-timesyncd 2>/dev/null
        
        apt install -y chrony >/dev/null 2>&1
        systemctl enable chrony >/dev/null 2>&1
        systemctl start chrony >/dev/null 2>&1
        
        local current_value="chrony active and enabled"
        local expected="chrony active and enabled"
        local status="PASS"
        
        log_fixed "$policy_name"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rollback for time sync will be handled by rollback script"
    fi
}

check_single_time_daemon() {
    local policy_id="SRV-3.c.i"
    local policy_name="Ensure a single time synchronization daemon is in use"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="only chrony running"
        local current="unknown"
        
        local chrony_active=$(systemctl is-active chrony 2>/dev/null)
        local timesyncd_active=$(systemctl is-active systemd-timesyncd 2>/dev/null)
        
        if [ "$chrony_active" = "active" ] && [ "$timesyncd_active" != "active" ]; then
            current="only chrony running"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="chrony: $chrony_active, timesyncd: $timesyncd_active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            local chrony_active=$(systemctl is-active chrony 2>/dev/null)
            local timesyncd_active=$(systemctl is-active systemd-timesyncd 2>/dev/null)
            original_value="chrony: $chrony_active, timesyncd: $timesyncd_active"
        fi
        
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        systemctl mask systemd-timesyncd 2>/dev/null
        
        local current_value="only chrony running"
        local expected="only chrony running"
        local status="PASS"
        
        log_fixed "$policy_name"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rollback will be handled by rollback script"
    fi
}

check_chrony_timeserver() {
    local policy_id="SRV-3.e.i"
    local policy_name="Ensure chrony is configured with authorized timeserver"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="timeserver configured"
        local current="unknown"
        
        if [ -f /etc/chrony/chrony.conf ] && grep -q "^pool\|^server" /etc/chrony/chrony.conf; then
            current=$(grep "^pool\|^server" /etc/chrony/chrony.conf | head -1 | awk '{print $2}')
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="no timeserver configured"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        log_manual "Chrony timeserver configuration requires manual setup"
        ((MANUAL_CHECKS++))
    fi
}

check_chrony_user() {
    local policy_id="SRV-3.e.ii"
    local policy_name="Ensure chrony is running as user _chrony"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="_chrony"
        local current="unknown"
        
        if ps -ef | grep chronyd | grep -v grep | grep -q "_chrony"; then
            current="_chrony"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current=$(ps -ef | grep chronyd | grep -v grep | awk '{print $1}' | head -1)
            if [ -z "$current" ]; then
                current="not running"
            fi
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
    fi
}

check_chrony_enabled() {
    local policy_id="SRV-3.e.iii"
    local policy_name="Ensure chrony is enabled and running"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="enabled and active"
        local current="unknown"
        
        local enabled=$(systemctl is-enabled chrony 2>/dev/null)
        local active=$(systemctl is-active chrony 2>/dev/null)
        
        if [ "$enabled" = "enabled" ] && [ "$active" = "active" ]; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enabled: $enabled, active: $active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            local enabled=$(systemctl is-enabled chrony 2>/dev/null)
            local active=$(systemctl is-active chrony 2>/dev/null)
            original_value="enabled: $enabled, active: $active"
        fi
        
        systemctl enable chrony >/dev/null 2>&1
        systemctl start chrony >/dev/null 2>&1
        
        local current_value="enabled and active"
        local expected="enabled and active"
        local status="PASS"
        
        log_fixed "$policy_name"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
        ((FIXED_CHECKS++))
    fi
}

# =========================
# Cron Job Schedulers
# =========================
check_cron_enabled() {
    local policy_id="SRV-3.f.i"
    local policy_name="Ensure cron daemon is enabled and active"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="enabled and active"
        local current="unknown"
        
        local enabled=$(systemctl is-enabled cron 2>/dev/null)
        local active=$(systemctl is-active cron 2>/dev/null)
        
        if [ "$enabled" = "enabled" ] && [ "$active" = "active" ]; then
            current="enabled and active"
            status="PASS"
            ((PASSED_CHECKS++))
        else
            current="enabled: $enabled, active: $active"
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$policy_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            local enabled=$(systemctl is-enabled cron 2>/dev/null)
            local active=$(systemctl is-active cron 2>/dev/null)
            original_value="enabled: $enabled, active: $active"
        fi
        
        systemctl enable cron >/dev/null 2>&1
        systemctl start cron >/dev/null 2>&1
        
        local current_value="enabled and active"
        local expected="enabled and active"
        local status="PASS"
        
        log_fixed "$policy_name"
        save_fix_result "$policy_id" "$policy_name" "$expected" "$original_value" "$current_value" "$status"
        ((FIXED_CHECKS++))
    fi
}

check_cron_permissions() {
    local file="$1"
    local policy_id="$2"
    local policy_name="$3"
    local expected_perms="$4"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local expected="$expected_perms root:root"
        local current="unknown"
        
        if [ -e "$file" ]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null)
            local owner=$(stat -c "%U:%G" "$file" 2>/dev/null)
            current="$perms $owner"
