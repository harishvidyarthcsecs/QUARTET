#!/bin/bash
# Filesystem Hardening Script
# Module: Filesystem
# Supports: scan, fix, rollback modes

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/filesystem"
ROLLBACK_SCRIPT="$SCRIPT_DIR/../rollback.bash"
TOPIC="Filesystem"
MODULE_NAME="Filesystem"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_manual() { echo -e "${CYAN}[MANUAL]${NC} $1"; }

# Track if fstab was modified
FSTAB_MODIFIED=false
FSTAB_BACKUP=""

# Initialize Database
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

print_check_result() {
    local policy_id="$1"
    local policy_name="$2"
    local expected="$3"
    local current="$4"
    local status="$5"
    
    # Apply color
    local status_colored="$status"
    case "$status" in
        PASS) status_colored="${GREEN}$status${NC}" ;;
        FAIL) status_colored="${RED}$status${NC}" ;;
        FIXED) status_colored="${BLUE}$status${NC}" ;;
        WARN) status_colored="${YELLOW}$status${NC}" ;;
        MANUAL) status_colored="${CYAN}$status${NC}" ;;
    esac
    
    echo "=============================================="
    echo "Module Name    : $MODULE_NAME"
    echo "Policy ID      : $policy_id"
    echo "Policy Name    : $policy_name"
    echo "Expected Value : $expected"
    echo "Current Value  : $current"
    echo -e "Status         : $status_colored"
    echo "=============================================="
}

# Save to scan_results table
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

# Save to fix_history table
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

# Get scan result from database
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

# ============================================================================
# NEW: IMPROVED PARTITION CHECKING LOGIC
# ============================================================================

# Check if directory is on separate partition
is_on_separate_partition() {
    local dir="$1"
    
    # Check if directory exists
    if [ ! -d "$dir" ]; then
        echo "DIR_NOT_EXIST"
        return 1
    fi
    
    # Get mount point for this directory
    local dir_mount
    dir_mount=$(df -P "$dir" 2>/dev/null | awk 'NR==2 {print $6}')
    
    # Get root mount point
    local root_mount
    root_mount=$(df -P / 2>/dev/null | awk 'NR==2 {print $6}')
    
    # If directory mount point equals the directory itself, it's a mount point
    if [ "$dir_mount" = "$dir" ]; then
        echo "SEPARATE"
        return 0
    # If directory is mounted at root, it's not separate
    elif [ "$dir_mount" = "/" ] && [ "$dir" != "/" ]; then
        echo "ON_ROOT"
        return 1
    # If mounted somewhere else
    elif [ -n "$dir_mount" ] && [ "$dir_mount" != "/" ]; then
        echo "SEPARATE"
        return 0
    else
        echo "UNKNOWN"
        return 1
    fi
}

# Get detailed partition info
get_partition_info() {
    local dir="$1"
    
    if [ ! -d "$dir" ]; then
        echo "Directory does not exist"
        return
    fi
    
    local device
    local fstype
    local mount_point
    local options
    
    # Use findmnt for more reliable info
    if command -v findmnt &> /dev/null; then
        device=$(findmnt -n -o SOURCE "$dir" 2>/dev/null)
        fstype=$(findmnt -n -o FSTYPE "$dir" 2>/dev/null)
        mount_point=$(findmnt -n -o TARGET "$dir" 2>/dev/null)
        options=$(findmnt -n -o OPTIONS "$dir" 2>/dev/null)
    else
        # Fallback to df and mount
        device=$(df -P "$dir" 2>/dev/null | awk 'NR==2 {print $1}')
        fstype=$(df -PT "$dir" 2>/dev/null | awk 'NR==2 {print $2}')
        mount_point=$(df -P "$dir" 2>/dev/null | awk 'NR==2 {print $6}')
        options=$(mount | grep " on $mount_point " | sed 's/.*(\(.*\))/\1/' 2>/dev/null)
    fi
    
    echo "Device: $device"
    echo "Filesystem: $fstype"
    echo "Mount point: $mount_point"
    echo "Options: $options"
}

# Check if partition has entry in fstab
has_fstab_entry() {
    local mount_point="$1"
    
    if [ ! -f "/etc/fstab" ]; then
        return 1
    fi
    
    # Check for exact mount point
    if grep -q "^[^#].*[[:space:]]${mount_point}[[:space:]]" /etc/fstab; then
        return 0
    fi
    
    # Check with escaped slashes for findmnt-like entries
    local escaped_mount=$(echo "$mount_point" | sed 's/\//\\\//g')
    if grep -q "^[^#].*[[:space:]]${mount_point}[[:space:]]" /etc/fstab; then
        return 0
    fi
    
    return 1
}

# Get fstab entry
get_fstab_entry() {
    local mount_point="$1"
    grep "^[^#].*[[:space:]]${mount_point}[[:space:]]" /etc/fstab 2>/dev/null | head -1
}

# Check if mount option is set
has_mount_option() {
    local mount_point="$1"
    local option="$2"
    
    local options
    if command -v findmnt &> /dev/null; then
        options=$(findmnt -n -o OPTIONS "$mount_point" 2>/dev/null)
    else
        options=$(mount | grep " on $mount_point " | sed 's/.*(\(.*\))/\1/' 2>/dev/null)
    fi
    
    if [[ ",$options," == *",$option,"* ]] || [[ "$options" == *"$option"* ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# 1.1 Filesystem Kernel Modules (Keep as is)
# ============================================================================

check_kernel_module() {
    local module="$1"
    local policy_num="$2"
    local rule_id="FS-1.a.${policy_num}"
    local rule_name="Ensure $module kernel module is not available"
    local expected="Module not loaded and blacklisted"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local is_loaded="No"
        local is_blacklisted="No"
        local status="FAIL"
        
        # Check if module is loaded
        if lsmod | grep -q "^$module "; then
            is_loaded="Yes"
        fi
        
        # Check if install directive exists
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            is_blacklisted="Yes"
        fi
        
        local current="Loaded: $is_loaded, Blacklisted: $is_blacklisted"
        
        if [ "$is_loaded" = "No" ] && [ "$is_blacklisted" = "Yes" ]; then
            status="PASS"
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
        fi
        
        print_check_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        save_scan_result "$rule_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$rule_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            # No scan data, get current state
            local is_loaded="No"
            local is_blacklisted="No"
            if lsmod | grep -q "^$module "; then
                is_loaded="Yes"
            fi
            if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
                is_blacklisted="Yes"
            fi
            original_value="Loaded: $is_loaded, Blacklisted: $is_blacklisted"
        fi
        
        local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
        
        # Backup original modprobe config if exists
        if [ -f "$modprobe_file" ]; then
            cp "$modprobe_file" "$BACKUP_DIR/$module-blacklist.conf.bak.$(date +%Y%m%d_%H%M%S)"
        fi
        
        cat > "$modprobe_file" << EOF
# Disable $module module - Added by hardening script
install $module /bin/false
blacklist $module
EOF
        
        if [ $? -eq 0 ]; then
            log_info "Created blacklist configuration: $modprobe_file"
            
            if lsmod | grep -q "^$module "; then
                if rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null; then
                    log_info "Module $module unloaded successfully"
                else
                    log_warn "Could not unload module $module (may require reboot)"
                fi
            fi
            
            local current_value="Loaded: No, Blacklisted: Yes"
            local status="PASS"
            
            log_pass "Module $module has been disabled"
            save_fix_result "$rule_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Checking rollback for $module module..."
        # Rollback logic will be handled by generate_rollback_script
    fi
}

check_all_kernel_modules() {
    log_info "=== 1.a Configure Filesystem Kernel Modules ==="
    
    check_kernel_module "cramfs" "i"
    check_kernel_module "freevxfs" "ii"
    check_kernel_module "hfs" "iii"
    check_kernel_module "hfsplus" "iv"
    check_kernel_module "jffs2" "v"
    check_kernel_module "overlayfs" "vi"
    check_kernel_module "squashfs" "vii"
    check_kernel_module "udf" "viii"
    check_kernel_module "usb-storage" "ix"
}

# ============================================================================
# NEW: IMPROVED PARTITION CHECKS
# ============================================================================

check_partition_exists() {
    local partition="$1"
    local policy_id="$2"
    local rule_name="Ensure $partition is a separate partition"
    local expected="Separate partition"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local result
        result=$(is_on_separate_partition "$partition")
        local status="FAIL"
        local current=""
        
        case "$result" in
            "SEPARATE")
                status="PASS"
                current="Separate partition"
                ((PASSED_CHECKS++))
                ;;
            "ON_ROOT")
                current="Mounted as part of root filesystem"
                ((FAILED_CHECKS++))
                ;;
            "DIR_NOT_EXIST")
                current="Directory does not exist"
                ((FAILED_CHECKS++))
                ;;
            *)
                current="Unknown status"
                ((FAILED_CHECKS++))
                ;;
        esac
        
        # Get additional info for display
        if [ "$partition" != "/" ] && [ -d "$partition" ]; then
            local mount_info
            mount_info=$(df -h "$partition" 2>/dev/null | awk 'NR==2 {print "Size:",$2,"Used:",$3,"Avail:",$4,"Use%:",$5,"Mounted:",$6}')
            if [ -n "$mount_info" ]; then
                current="$current ($mount_info)"
            fi
        fi
        
        print_check_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Check current state
        local result
        result=$(is_on_separate_partition "$partition")
        
        if [ "$result" = "SEPARATE" ]; then
            log_pass "$partition is already a separate partition"
            return 0
        fi
        
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            original_value="$result"
        fi
        
        # Display manual instructions for creating separate partition
        echo ""
        echo -e "${CYAN}=======================================================================${NC}"
        echo -e "${YELLOW}MANUAL ACTION REQUIRED:${NC} Create separate partition for $partition"
        echo -e "${CYAN}=======================================================================${NC}"
        echo ""
        echo -e "${GREEN}Steps to create separate partition:${NC}"
        echo "1. Check available disk space:"
        echo "   # fdisk -l"
        echo "   # lsblk"
        echo ""
        echo "2. Create new partition using one of:"
        echo "   # fdisk /dev/sdX"
        echo "   # parted /dev/sdX"
        echo "   # gdisk /dev/sdX (for GPT)"
        echo ""
        echo "3. Create filesystem on new partition:"
        echo "   # mkfs.ext4 /dev/sdXN"
        echo ""
        echo "4. Create mount point if needed:"
        echo "   # mkdir -p $partition"
        echo ""
        echo "5. Move existing data (if any):"
        echo "   # cp -ax $partition/* /mnt/temp/"
        echo ""
        echo "6. Add entry to /etc/fstab:"
        echo "   /dev/sdXN  $partition  ext4  defaults  0 0"
        echo ""
        echo "7. Mount the new partition:"
        echo "   # mount -a"
        echo ""
        echo -e "${YELLOW}Note:${NC} These steps require manual intervention and careful planning."
        echo -e "${YELLOW}Warning:${NC} Partitioning can lead to data loss if done incorrectly!"
        echo ""
        
        # Update status to indicate manual action required
        local current_value="MANUAL ACTION REQUIRED"
        local status="MANUAL"
        
        print_check_result "$policy_id" "$rule_name" "$expected" "$current_value" "$status"
        save_fix_result "$policy_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
        ((MANUAL_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Checking rollback for $partition partition existence..."
    fi
}

check_partition_option() {
    local partition="$1"
    local option="$2"
    local policy_id="$3"
    local rule_name="Ensure $option option set on $partition partition"
    local expected="$option"
    
    ((TOTAL_CHECKS++))
    
    if [ "$MODE" = "scan" ]; then
        local status="FAIL"
        local current=""
        
        # Check if directory exists
        if [ ! -d "$partition" ] && [ "$partition" != "/dev/shm" ]; then
            current="Directory does not exist"
            ((FAILED_CHECKS++))
        else
            # First check if it's a separate partition
            local partition_status
            partition_status=$(is_on_separate_partition "$partition")
            
            if [ "$partition_status" != "SEPARATE" ]; then
                current="Not a separate partition"
                ((FAILED_CHECKS++))
            else
                # Check mount option
                if has_mount_option "$partition" "$option"; then
                    status="PASS"
                    current="$option option is set"
                    ((PASSED_CHECKS++))
                else
                    current="$option option is NOT set"
                    ((FAILED_CHECKS++))
                    
                    # Get current options
                    local current_opts
                    if command -v findmnt &> /dev/null; then
                        current_opts=$(findmnt -n -o OPTIONS "$partition" 2>/dev/null)
                    else
                        current_opts=$(mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/' 2>/dev/null)
                    fi
                    
                    if [ -n "$current_opts" ]; then
                        current="$current (current options: $current_opts)"
                    fi
                fi
            fi
        fi
        
        print_check_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        save_scan_result "$policy_id" "$rule_name" "$expected" "$current" "$status"
        
    elif [ "$MODE" = "fix" ]; then
        # Check if directory exists
        if [ ! -d "$partition" ] && [ "$partition" != "/dev/shm" ]; then
            log_error "Directory $partition does not exist"
            return 1
        fi
        
        # Check if it's a separate partition
        local partition_status
        partition_status=$(is_on_separate_partition "$partition")
        
        if [ "$partition_status" != "SEPARATE" ]; then
            log_error "Cannot set mount options: $partition is not a separate partition"
            ((MANUAL_CHECKS++))
            return 1
        fi
        
        # Check if already has the option
        if has_mount_option "$partition" "$option"; then
            log_pass "$partition already has $option option"
            return 0
        fi
        
        # Get original state from scan
        local scan_data
        scan_data=$(get_scan_result "$policy_id")
        local original_value=$(echo "$scan_data" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('current_value', ''))")
        
        if [ -z "$original_value" ]; then
            # Get current options
            local current_opts
            if command -v findmnt &> /dev/null; then
                current_opts=$(findmnt -n -o OPTIONS "$partition" 2>/dev/null)
            else
                current_opts=$(mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/' 2>/dev/null)
            fi
            original_value="$option option is NOT set (current: $current_opts)"
        fi
        
        # Check if partition has entry in fstab
        if ! has_fstab_entry "$partition"; then
            echo ""
            echo -e "${CYAN}=======================================================================${NC}"
            echo -e "${YELLOW}MANUAL ACTION REQUIRED:${NC} No fstab entry found for $partition"
            echo -e "${CYAN}=======================================================================${NC}"
            echo ""
            echo -e "${GREEN}To add mount options:${NC}"
            echo "1. Check current mount:"
            echo "   # mount | grep '$partition'"
            echo ""
            echo "2. Add entry to /etc/fstab. Example:"
            echo "   /dev/sdXN  $partition  ext4  defaults,$option  0 0"
            echo ""
            echo "3. Apply changes:"
            echo "   # mount -o remount $partition"
            echo ""
            
            local current_value="MANUAL ACTION REQUIRED - No fstab entry"
            local status="MANUAL"
            
            print_check_result "$policy_id" "$rule_name" "$expected" "$current_value" "$status"
            save_fix_result "$policy_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
            ((MANUAL_CHECKS++))
            return 1
        fi
        
        # Backup fstab before modification
        if [ -z "$FSTAB_BACKUP" ]; then
            FSTAB_BACKUP="$BACKUP_DIR/fstab.backup.$(date +%Y%m%d_%H%M%S)"
            cp /etc/fstab "$FSTAB_BACKUP"
            log_info "Backed up fstab to: $FSTAB_BACKUP"
        fi
        
        # Update fstab entry
        local temp_file
        temp_file=$(mktemp)
        local updated=false
        
        while IFS= read -r line; do
            # Check if this is the partition line
            if echo "$line" | grep -q "^[^#].*[[:space:]]${partition}[[:space:]]"; then
                # Parse the line
                local device=$(echo "$line" | awk '{print $1}')
                local mp=$(echo "$line" | awk '{print $2}')
                local fstype=$(echo "$line" | awk '{print $3}')
                local opts=$(echo "$line" | awk '{print $4}')
                local dump=$(echo "$line" | awk '{print $5}')
                local pass=$(echo "$line" | awk '{print $6}')
                
                # Update options
                if [[ ",$opts," != *",$option,"* ]]; then
                    if [ "$opts" = "defaults" ]; then
                        opts="defaults,$option"
                    else
                        opts="$opts,$option"
                    fi
                    updated=true
                    FSTAB_MODIFIED=true
                fi
                
                # Write updated line
                printf "%-20s %-15s %-10s %-30s %s %s\n" "$device" "$mp" "$fstype" "$opts" "$dump" "$pass" >> "$temp_file"
            else
                # Write unchanged line
                echo "$line" >> "$temp_file"
            fi
        done < /etc/fstab
        
        if [ "$updated" = true ]; then
            # Replace fstab
            if mv "$temp_file" /etc/fstab; then
                chmod 644 /etc/fstab
                log_info "Updated fstab for $partition with $option option"
                
                # Try to remount
                if mount -o remount "$partition" 2>/dev/null; then
                    log_pass "Successfully remounted $partition with $option option"
                    local current_value="$option option has been set"
                    local status="PASS"
                else
                    log_warn "Updated fstab but could not remount $partition"
                    log_warn "Run 'mount -o remount $partition' manually or reboot"
                    local current_value="$option option added to fstab (remount required)"
                    local status="WARN"
                fi
                
                save_fix_result "$policy_id" "$rule_name" "$expected" "$original_value" "$current_value" "$status"
                ((FIXED_CHECKS++))
            else
                log_error "Failed to update /etc/fstab"
                return 1
            fi
        else
            log_info "$partition already has $option option in fstab"
            rm -f "$temp_file"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Checking rollback for $partition $option option..."
    fi
}

# ============================================================================
# Partition Configuration Functions
# ============================================================================

check_tmp_partition() {
    log_info "=== 1.b Configure /tmp ==="
    check_partition_exists "/tmp" "FS-1.b.i"
    check_partition_option "/tmp" "nodev" "FS-1.b.ii"
    check_partition_option "/tmp" "nosuid" "FS-1.b.iii"
    check_partition_option "/tmp" "noexec" "FS-1.b.iv"
}

check_dev_shm_partition() {
    log_info "=== 1.c Configure /dev/shm ==="
    check_partition_exists "/dev/shm" "FS-1.c.i"
    check_partition_option "/dev/shm" "nodev" "FS-1.c.ii"
    check_partition_option "/dev/shm" "nosuid" "FS-1.c.iii"
    check_partition_option "/dev/shm" "noexec" "FS-1.c.iv"
}

check_home_partition() {
    log_info "=== 1.d Configure /home ==="
    check_partition_exists "/home" "FS-1.d.i"
    check_partition_option "/home" "nodev" "FS-1.d.ii"
    check_partition_option "/home" "nosuid" "FS-1.d.iii"
}

check_var_partition() {
    log_info "=== 1.e Configure /var ==="
    check_partition_exists "/var" "FS-1.e.i"
    check_partition_option "/var" "nodev" "FS-1.e.ii"
    check_partition_option "/var" "nosuid" "FS-1.e.iii"
}

check_var_tmp_partition() {
    log_info "=== 1.f Configure /var/tmp ==="
    check_partition_exists "/var/tmp" "FS-1.f.i"
    check_partition_option "/var/tmp" "nodev" "FS-1.f.ii"
    check_partition_option "/var/tmp" "nosuid" "FS-1.f.iii"
    check_partition_option "/var/tmp" "noexec" "FS-1.f.iv"
}

check_var_log_partition() {
    log_info "=== 1.g Configure /var/log ==="
    check_partition_exists "/var/log" "FS-1.g.i"
    check_partition_option "/var/log" "nodev" "FS-1.g.ii"
    check_partition_option "/var/log" "nosuid" "FS-1.g.iii"
    check_partition_option "/var/log" "noexec" "FS-1.g.iv"
}

check_var_log_audit_partition() {
    log_info "=== 1.h Configure /var/log/audit ==="
    check_partition_exists "/var/log/audit" "FS-1.h.i"
    check_partition_option "/var/log/audit" "nodev" "FS-1.h.ii"
    check_partition_option "/var/log/audit" "nosuid" "FS-1.h.iii"
    check_partition_option "/var/log/audit" "noexec" "FS-1.h.iv"
}

# ============================================================================
# Generate Rollback Script
# ============================================================================

generate_rollback_script() {
    log_info "Generating rollback script..."
    
    python3 << 'PYTHON_SCRIPT'
import sqlite3
import sys
import os

DB_PATH = os.environ.get('DB_PATH')
ROLLBACK_SCRIPT = os.environ.get('ROLLBACK_SCRIPT')
MODULE_NAME = os.environ.get('MODULE_NAME')
BACKUP_DIR = os.environ.get('BACKUP_DIR')

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all items that were fixed but need rollback
    cursor.execute('''
        SELECT f.policy_id, f.policy_name, f.original_value, s.current_value, s.status
        FROM fix_history f
        LEFT JOIN scan_results s ON f.module_name = s.module_name AND f.policy_id = s.policy_id
        WHERE f.module_name = ? AND f.rollback_executed = 'NO'
    ''', (MODULE_NAME,))
    
    fixes = cursor.fetchall()
    
    if not fixes:
        print("No fixes found to rollback")
        conn.close()
        sys.exit(0)
    
    # Generate rollback script
    script_content = '''#!/bin/bash
# Auto-generated Rollback Script for Filesystem Module
# Generated at: ''' + os.popen('date').read().strip() + '''

BACKUP_DIR="''' + BACKUP_DIR + '''"
MODULE="''' + MODULE_NAME + '''"

echo "========================================================================"
echo "Rollback Script for $MODULE Module"
echo "========================================================================"

'''
    
    for fix in fixes:
        policy_id, policy_name, original_value, scan_current, scan_status = fix
        
        # Kernel modules rollback
        if 'kernel module' in policy_name.lower():
            module_name = policy_name.split()[1]
            if 'not available' in policy_name:
                script_content += f'''
# Rollback: {policy_name}
echo "Rolling back {module_name} module configuration..."
if [ -f "/etc/modprobe.d/{module_name}-blacklist.conf" ]; then
    # Check if we have a backup
    LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/{module_name}-blacklist.conf.bak.* 2>/dev/null | head -1)
    if [ -n "$LATEST_BACKUP" ]; then
        cp "$LATEST_BACKUP" "/etc/modprobe.d/{module_name}-blacklist.conf"
        echo "Restored {module_name} config from backup"
    else
        rm -f "/etc/modprobe.d/{module_name}-blacklist.conf"
        echo "Removed {module_name} blacklist (no backup found)"
    fi
fi
modprobe {module_name} 2>/dev/null && echo "Loaded {module_name} module" || echo "Note: Could not load {module_name} module"

'''
        
        # Partition options rollback
        elif 'option set on' in policy_name.lower():
            # Extract partition from policy name
            parts = policy_name.split()
            for i, part in enumerate(parts):
                if part == 'on':
                    partition = parts[i + 1]
                    break
            
            script_content += f'''
# Rollback: {policy_name}
echo "Rolling back mount options for {partition}..."
LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/fstab.backup.* 2>/dev/null | head -1)
if [ -n "$LATEST_BACKUP" ]; then
    cp "$LATEST_BACKUP" /etc/fstab
    echo "Restored fstab from backup"
    if mount | grep -q " on {partition} "; then
        mount -o remount {partition} 2>/dev/null
        echo "Remounted {partition} with original options"
    fi
else:
    echo "Warning: No fstab backup found for {partition}"
fi

'''
    
    script_content += '''
echo "========================================================================"
echo "Rollback completed"
echo "========================================================================"

# Mark rollback as executed in database
python3 << 'EOF'
import sqlite3
DB_PATH = "''' + DB_PATH + '''"
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE fix_history SET rollback_executed='YES' WHERE module_name=? AND rollback_executed='NO'", ("''' + MODULE_NAME + '''",))
    conn.commit()
    conn.close()
    print("Database updated: Rollback marked as executed")
except Exception as e:
    print(f"Error updating database: {e}")
EOF
'''
    
    # Write rollback script
    with open(ROLLBACK_SCRIPT, 'w') as f:
        f.write(script_content)
    
    os.chmod(ROLLBACK_SCRIPT, 0o755)
    print(f"Rollback script generated: {ROLLBACK_SCRIPT}")
    
    conn.close()
    
except sqlite3.Error as e:
    print(f'Database error: {e}', file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)

PYTHON_SCRIPT
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Filesystem Hardening Script"
    echo "Module: $MODULE_NAME"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    # Initialize database
    init_database
    
    if [ "$MODE" = "fix" ] || [ "$MODE" = "rollback" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "This script must be run as root for $MODE mode"
            exit 1
        fi
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_kernel_modules
        check_tmp_partition
        check_dev_shm_partition
        check_home_partition
        check_var_partition
        check_var_tmp_partition
        check_var_log_partition
        check_var_log_audit_partition
        
        if [ "$MODE" = "fix" ]; then
            # Generate rollback script after fixes
            generate_rollback_script
            
            # Apply fstab changes if modified
            if [ "$FSTAB_MODIFIED" = "true" ]; then
                echo ""
                log_info "Applying fstab changes..."
                
                # Test fstab syntax
                if mount -a --test 2>/dev/null; then
                    log_info "fstab syntax is valid"
                    
                    # Remount partitions with new options
                    local mount_success=true
                    for part in /var/log/audit /var/log /var/tmp /var /home /tmp /dev/shm; do
                        if mount | grep -q " on $part " 2>/dev/null; then
                            if mount -o remount "$part" 2>/dev/null; then
                                log_pass "Remounted $part with new options"
                            else
                                log_warn "Could not remount $part (might require reboot)"
                                mount_success=false
                            fi
                        fi
                    done
                    
                    if [ "$mount_success" = "false" ]; then
                        log_warn "Some partitions could not be remounted"
                        log_warn "Run 'mount -o remount /partition' manually or reboot"
                    fi
                else
                    log_error "fstab has syntax errors!"
                    log_info "Restoring from backup..."
                    if [ -n "$FSTAB_BACKUP" ] && [ -f "$FSTAB_BACKUP" ]; then
                        cp "$FSTAB_BACKUP" /etc/fstab
                        log_info "Restored fstab from backup"
                    fi
                fi
            fi
        fi
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All filesystem checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            echo "Manual Actions Required: $MANUAL_CHECKS"
            
            if [ $MANUAL_CHECKS -gt 0 ]; then
                echo ""
                log_manual "$MANUAL_CHECKS checks require manual intervention"
                log_manual "Please follow the instructions shown above"
            fi
            
            if [ $FIXED_CHECKS -gt 0 ]; then
                echo ""
                log_info "Rollback script has been generated at: $ROLLBACK_SCRIPT"
                log_info "To rollback changes, run: sudo bash $ROLLBACK_SCRIPT"
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        if [ -f "$ROLLBACK_SCRIPT" ]; then
            log_info "Executing rollback script: $ROLLBACK_SCRIPT"
            bash "$ROLLBACK_SCRIPT"
        else
            log_error "Rollback script not found: $ROLLBACK_SCRIPT"
            log_info "Attempting to generate rollback script from database..."
            generate_rollback_script
            
            if [ -f "$ROLLBACK_SCRIPT" ]; then
                log_info "Executing generated rollback script..."
                bash "$ROLLBACK_SCRIPT"
            else
                log_error "Failed to generate rollback script"
                exit 1
            fi
        fi
        
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
