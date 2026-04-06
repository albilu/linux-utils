#!/bin/bash

# Chroot Helper Script
# Helps mount and chroot into an installed Linux system

# Wrap the entire script in a function so that bash reads it fully from stdin
# before executing. This allows `curl | bash` to work with interactive prompts.
_entry() {
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
MOUNT_POINT="/mnt"
ROOT_DEVICE=""
BOOT_DEVICE=""
IS_ENCRYPTED=false
LUKS_NAME=""
IS_LVM=false
LVM_VG=""
LVM_LV=""

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to list available block devices
list_devices() {
    print_info "Available block devices:"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT | grep -v "loop"
    echo ""
}

# Function to check if device is encrypted
check_encryption() {
    local device=$1
    if cryptsetup isLuks "$device" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to decrypt LUKS device
decrypt_device() {
    local device=$1
    local default_name=$(basename "$device")_crypt
    
    print_info "Device $device is encrypted"
    read -p "Enter name for decrypted device (default: $default_name): " LUKS_NAME
    LUKS_NAME=${LUKS_NAME:-$default_name}
    
    # Check if already opened
    if [[ -e "/dev/mapper/$LUKS_NAME" ]]; then
        print_warning "Device already decrypted at /dev/mapper/$LUKS_NAME"
        return 0
    fi
    
    print_info "Opening LUKS device..."
    if cryptsetup luksOpen "$device" "$LUKS_NAME"; then
        print_success "Device decrypted to /dev/mapper/$LUKS_NAME"
        return 0
    else
        print_error "Failed to decrypt device"
        return 1
    fi
}

# Function to detect LVM
detect_lvm() {
    local device=$1
    
    # Check if device is an LVM logical volume
    if lvdisplay "$device" &>/dev/null; then
        IS_LVM=true
        LVM_VG=$(lvdisplay "$device" | grep "VG Name" | awk '{print $3}')
        LVM_LV=$(lvdisplay "$device" | grep "LV Name" | awk '{print $3}')
        print_info "Detected LVM: VG=$LVM_VG, LV=$LVM_LV"
        return 0
    fi
    
    # Check if this is a physical volume containing VGs
    if pvdisplay "$device" &>/dev/null; then
        IS_LVM=true
        print_info "Device is an LVM physical volume"
        vgchange -ay
        print_success "LVM volume groups activated"
        return 0
    fi
    
    return 1
}

# Function to select root device
select_root_device() {
    list_devices

    local DEV_NAMES=()
    local DEV_LINES=()
    local name line
    while IFS= read -r name; do
        line=$(lsblk -d -n -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT "/dev/${name}" 2>/dev/null || true)
        DEV_NAMES+=("$name")
        DEV_LINES+=("$line")
    done < <(lsblk -ln -o NAME,TYPE | awk '$2=="part" || $2=="dm" {print $1}')

    if [[ ${#DEV_NAMES[@]} -eq 0 ]]; then
        print_error "No partitions or device-mapper devices found"
        exit 1
    fi

    echo "Available devices:"
    local i
    for (( i=0; i<${#DEV_NAMES[@]}; i++ )); do
        printf "  %d) %s\n" "$((i+1))" "${DEV_LINES[$i]}"
    done
    echo ""

    while true; do
        read -rp "Enter root device number (1-${#DEV_NAMES[@]}): " choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || \
           [[ "$choice" -lt 1 ]] || \
           [[ "$choice" -gt ${#DEV_NAMES[@]} ]]; then
            print_error "Invalid selection: $choice"
            continue
        fi

        ROOT_DEVICE="/dev/${DEV_NAMES[$((choice-1))]}"

        if [[ ! -b "$ROOT_DEVICE" ]]; then
            print_error "Not a block device: $ROOT_DEVICE"
            continue
        fi

        # Check if encrypted
        if check_encryption "$ROOT_DEVICE"; then
            IS_ENCRYPTED=true
            if ! decrypt_device "$ROOT_DEVICE"; then
                continue
            fi
            ROOT_DEVICE="/dev/mapper/$LUKS_NAME"
        fi

        # Activate LVM if present
        detect_lvm "$ROOT_DEVICE"

        # If LVM physical volume was detected, must select a logical volume
        if [[ $IS_LVM == true ]]; then
            mapfile -t LV_PATHS < <(lvs --noheadings -o lv_path,lv_name \
                | awk '$2 !~ /[Ss]wap/ {print $1}')

            if [[ ${#LV_PATHS[@]} -eq 0 ]]; then
                print_error "No non-swap logical volumes found"
                exit 1
            elif [[ ${#LV_PATHS[@]} -eq 1 ]]; then
                ROOT_DEVICE="${LV_PATHS[0]}"
                print_info "Auto-selected root LV: $ROOT_DEVICE"
            else
                echo "Available logical volumes:"
                local j
                for j in "${!LV_PATHS[@]}"; do
                    local lv_path="${LV_PATHS[$j]}"
                    local lv_display
                    lv_display=$(lvs --noheadings -o lv_path,lv_size,vg_name "$lv_path" 2>/dev/null | head -1)
                    printf "  %d) %s\n" "$((j+1))" "$lv_display"
                done
                echo ""

                while true; do
                    read -rp "Enter LV number (1-${#LV_PATHS[@]}): " lv_choice

                    if ! [[ "$lv_choice" =~ ^[0-9]+$ ]] || \
                       [[ "$lv_choice" -lt 1 ]] || \
                       [[ "$lv_choice" -gt ${#LV_PATHS[@]} ]]; then
                        print_error "Invalid selection: $lv_choice"
                        continue
                    fi

                    ROOT_DEVICE="${LV_PATHS[$((lv_choice-1))]}"

                    if [[ ! -b "$ROOT_DEVICE" ]]; then
                        print_error "Not a block device: $ROOT_DEVICE"
                        continue
                    fi
                    break
                done
            fi
        fi

        print_success "Selected root device: $ROOT_DEVICE"
        break
    done
}

# Function to select boot device
select_boot_device() {
    list_devices

    local DEV_NAMES=()
    local DEV_LINES=()
    local name line
    while IFS= read -r name; do
        line=$(lsblk -d -n -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT "/dev/${name}" 2>/dev/null || true)
        DEV_NAMES+=("$name")
        DEV_LINES+=("$line")
    done < <(lsblk -ln -o NAME,TYPE | awk '$2=="part" || $2=="dm" {print $1}')

    if [[ ${#DEV_NAMES[@]} -eq 0 ]]; then
        print_info "No devices found — skipping boot partition mount"
        BOOT_DEVICE=""
        return 0
    fi

    echo "Available devices:"
    printf "  0) Skip (no boot/EFI partition)\n"
    local i
    for (( i=0; i<${#DEV_NAMES[@]}; i++ )); do
        printf "  %d) %s\n" "$((i+1))" "${DEV_LINES[$i]}"
    done
    echo ""

    while true; do
        read -rp "Enter boot device number (0 to skip, 1-${#DEV_NAMES[@]}): " choice

        if [[ "$choice" == "0" ]]; then
            BOOT_DEVICE=""
            print_info "Skipping boot partition mount"
            break
        fi

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || \
           [[ "$choice" -lt 1 ]] || \
           [[ "$choice" -gt ${#DEV_NAMES[@]} ]]; then
            print_error "Invalid selection: $choice"
            continue
        fi

        BOOT_DEVICE="/dev/${DEV_NAMES[$((choice-1))]}"

        if [[ ! -b "$BOOT_DEVICE" ]]; then
            print_error "Not a block device: $BOOT_DEVICE"
            continue
        fi

        print_success "Selected boot device: $BOOT_DEVICE"
        break
    done
}

# Function to mount root filesystem
mount_root() {
    print_info "Mounting root filesystem..."
    
    if mountpoint -q "$MOUNT_POINT"; then
        print_warning "$MOUNT_POINT is already mounted"
    else
        mkdir -p "$MOUNT_POINT"
        if mount "$ROOT_DEVICE" "$MOUNT_POINT"; then
            print_success "Root filesystem mounted at $MOUNT_POINT"
        else
            print_error "Failed to mount root filesystem"
            exit 1
        fi
    fi
}

# Function to mount boot filesystem
mount_boot() {
    if [[ -z "$BOOT_DEVICE" ]]; then
        return 0
    fi
    
    print_info "Mounting boot/EFI filesystem..."
    
    # Detect boot directory (could be /boot/efi or /boot)
    local boot_dir=""
    if [[ -d "$MOUNT_POINT/boot/efi" ]]; then
        boot_dir="$MOUNT_POINT/boot/efi"
    elif [[ -d "$MOUNT_POINT/boot" ]]; then
        boot_dir="$MOUNT_POINT/boot"
    else
        print_warning "Boot directory not found, creating /boot/efi"
        mkdir -p "$MOUNT_POINT/boot/efi"
        boot_dir="$MOUNT_POINT/boot/efi"
    fi
    
    if mountpoint -q "$boot_dir"; then
        print_warning "$boot_dir is already mounted"
    else
        if mount "$BOOT_DEVICE" "$boot_dir"; then
            print_success "Boot filesystem mounted at $boot_dir"
        else
            print_error "Failed to mount boot filesystem"
        fi
    fi
}

# Function to bind mount system directories
bind_mount_system() {
    print_info "Bind mounting system directories..."
    
    local dirs=("/sys" "/proc" "/run" "/dev" "/dev/pts")
    
    for dir in "${dirs[@]}"; do
        local target="$MOUNT_POINT$dir"
        mkdir -p "$target"
        
        if mountpoint -q "$target"; then
            print_warning "$target is already mounted"
        else
            if mount --bind "$dir" "$target"; then
                print_success "Bind mounted $dir"
            else
                print_warning "Failed to bind mount $dir"
            fi
        fi
    done
}

# Function to enter chroot
enter_chroot() {
    print_info "Entering chroot environment..."
    print_info "Type 'exit' to leave the chroot environment"
    echo ""
    
    chroot "$MOUNT_POINT" /bin/bash
}

# Function to cleanup and unmount
cleanup() {
    print_info "Cleaning up..."
    
    # Unmount bind mounts
    local dirs=("/dev/pts" "/dev" "/run" "/proc" "/sys")
    for dir in "${dirs[@]}"; do
        local target="$MOUNT_POINT$dir"
        if mountpoint -q "$target"; then
            umount "$target" 2>/dev/null || print_warning "Failed to unmount $target"
        fi
    done
    
    # Unmount boot
    if [[ -n "$BOOT_DEVICE" ]]; then
        local boot_dir=""
        if mountpoint -q "$MOUNT_POINT/boot/efi"; then
            boot_dir="$MOUNT_POINT/boot/efi"
        elif mountpoint -q "$MOUNT_POINT/boot"; then
            boot_dir="$MOUNT_POINT/boot"
        fi
        
        if [[ -n "$boot_dir" ]]; then
            umount "$boot_dir" 2>/dev/null || print_warning "Failed to unmount $boot_dir"
        fi
    fi
    
    # Unmount root
    if mountpoint -q "$MOUNT_POINT"; then
        umount "$MOUNT_POINT" 2>/dev/null || print_warning "Failed to unmount $MOUNT_POINT"
    fi
    
    # Close LUKS device
    if [[ $IS_ENCRYPTED == true ]] && [[ -n "$LUKS_NAME" ]]; then
        if [[ -e "/dev/mapper/$LUKS_NAME" ]]; then
            cryptsetup luksClose "$LUKS_NAME" 2>/dev/null || print_warning "Failed to close LUKS device"
        fi
    fi
    
    print_success "Cleanup completed"
}

# Main function
main() {
    check_root
    
    print_info "Chroot Helper Script"
    echo ""
    
    # Select devices
    select_root_device
    select_boot_device
    
    # Mount filesystems
    mount_root
    mount_boot
    bind_mount_system
    
    # Enter chroot
    enter_chroot
    
    # Cleanup after exit
    echo ""
    read -p "Do you want to unmount and cleanup? (y/n): " cleanup_choice
    if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
        cleanup
    else
        print_info "Leaving filesystems mounted. Run this script again or manually unmount when done."
    fi
}

# Trap to ensure cleanup on script exit
trap 'print_error "Script interrupted"; exit 1' INT TERM

# Run main function
main
}

_entry "$@" </dev/tty
