#!/bin/bash

# Debian-based Secure Installer with Full Disk Encryption and UEFI Secure Boot
# This script automates the installation of a Debian-based system with:
# - Support for Debian, Kali Linux, and PureOS
# - LUKS1/LUKS2 full disk encryption (auto-detects GRUB version)
# - LVM volume management
# - fscrypt encrypted /home directories (ext4 native encryption)
# - UEFI Secure Boot with custom keys
# - Automated GRUB signing on kernel updates
# - RAM swiper for cold boot attack mitigation
# - NetworkManager for network management
# - Pipewire/PulseAudio audio system
# - Bluetooth support
# - UFW firewall configuration
# - Optional desktop environment installation (GNOME, KDE, XFCE, etc.)
# - TPM 2.0 detection: reports TPM version and availability

# Wrap the entire script in a function so that bash reads it fully from stdin
# before executing. This allows `curl | bash` to work with interactive prompts.
_entry() {
# At this point bash has fully read the function body from stdin (the pipe),
# so it is safe to permanently redirect stdin to the real terminal.
exec </dev/tty
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
KEYS_LOCATION="/etc/sb_keys"
MOUNT_POINT="/mnt/target"
ISO_MOUNT="/mnt/iso"
EFI_SIZE="512" # MB
SWAP_SIZE="" # Will be set interactively
TARGET_DISK=""
LUKS_PASS=""
VG_NAME="system-vg" # Will be set after DISTRO_NAME is determined
HOSTNAME=""
USERNAME=""
DISTRO_NAME="debian"
LUKS_VERSION="luks1"
GRUB_VERSION=""
TIMEZONE=""
LOCALE=""
KEYBOARD_LAYOUT=""
KEYBOARD_VARIANT=""
TPM_AVAILABLE="no"
TPM_VERSION=""
SECURE_BOOT_STATE="unknown"
EFI_BOOT_ID="debian" # EFI bootloader-id: 'debian' for Debian/PureOS (strict), 'kali' for Kali

# Get script directory for log file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/debian-secure-installer_$(date +%Y%m%d_%H%M%S).log"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Check for UEFI support
check_uefi() {
    log "Checking UEFI support..."
    if [[ ! -d /sys/firmware/efi ]]; then
        error "System not booted in UEFI mode. This installer requires UEFI."
        exit 1
    fi
    log "UEFI mode detected"
}

# Check Secure Boot status
check_secure_boot() {
    log "Checking Secure Boot status..."
    
    # Method 1: Check EFI variables directly (no dependencies required)
    local sb_var="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    local setup_var="/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    
    SECURE_BOOT_STATE="unknown"  # Reset to unknown before checking
    
    if [[ -f "$sb_var" ]]; then
        # Read the last byte of the variable (the actual value)
        local sb_enabled=$(od -An -t u1 "$sb_var" | awk '{print $NF}')
        local setup_mode=0
        
        if [[ -f "$setup_var" ]]; then
            setup_mode=$(od -An -t u1 "$setup_var" | awk '{print $NF}')
        fi
        
        if [[ "$sb_enabled" == "1" ]]; then
            if [[ "$setup_mode" == "1" ]]; then
                SECURE_BOOT_STATE="Enabled (Setup Mode)"
                info "Secure Boot state: $SECURE_BOOT_STATE"
                warning "System is in Setup Mode - custom keys can be enrolled"
            else
                SECURE_BOOT_STATE="Enabled"
                info "Secure Boot state: $SECURE_BOOT_STATE"
            fi
        else
            SECURE_BOOT_STATE="Disabled"
            info "Secure Boot state: $SECURE_BOOT_STATE"
        fi
    # Method 2: Fallback to mokutil if available
    elif command -v mokutil &> /dev/null; then
        SECURE_BOOT_STATE=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        info "Secure Boot state: $SECURE_BOOT_STATE"
    else
        SECURE_BOOT_STATE="unknown"
        warning "Cannot determine Secure Boot state (no EFI variables or mokutil)"
    fi
}

# Check TPM support
check_tpm_support() {
    log "Checking TPM support..."

    # Check if any TPM device exists in sysfs
    if [[ ! -d /sys/class/tpm ]] || [[ -z "$(ls /sys/class/tpm/ 2>/dev/null)" ]]; then
        info "No TPM device detected"
        TPM_AVAILABLE="no"
        return 1
    fi

    local tpm_dir
    tpm_dir=$(ls /sys/class/tpm/ | head -1)

    # Detect TPM version
    if [[ -f /sys/class/tpm/${tpm_dir}/tpm_version_major ]]; then
        TPM_VERSION=$(cat /sys/class/tpm/${tpm_dir}/tpm_version_major 2>/dev/null)
    elif [[ -c /dev/tpmrm0 ]]; then
        # /dev/tpmrm0 (resource manager) is only present for TPM 2.0
        TPM_VERSION="2"
    elif [[ -f /sys/class/tpm/${tpm_dir}/caps ]]; then
        # 'caps' file is characteristic of TPM 1.x
        TPM_VERSION="1"
    else
        TPM_VERSION="unknown"
    fi

    if [[ "$TPM_VERSION" != "2" ]]; then
        warning "TPM ${TPM_VERSION}.x detected — auto-unlock requires TPM 2.0"
        TPM_AVAILABLE="no"
        return 1
    fi

    # Verify TPM2 is functional
    if command -v tpm2_getcap &>/dev/null; then
        if ! tpm2_getcap properties-fixed &>/dev/null; then
            warning "TPM2 device found but not responding — check that TPM is enabled in UEFI."
            TPM_AVAILABLE="no"
            return 1
        fi
    else
        # tpm2-tools not yet installed; confirm at least one device node exists
        if [[ ! -c /dev/tpm0 ]] && [[ ! -c /dev/tpmrm0 ]]; then
            warning "TPM2 sysfs entry found but no device node (/dev/tpm0 or /dev/tpmrm0)"
            TPM_AVAILABLE="no"
            return 1
        fi
    fi

    TPM_AVAILABLE="yes"
    log "TPM 2.0 detected and available"
    info "TPM2 detected — PCR measurements will be recorded by the GRUB tpm module"
    info "This supports remote attestation and future use cases"
    return 0
}

# Query target repository for GRUB version
check_target_grub_version() {
    log "Querying target repository for GRUB version..."
    
    local repo_url=""
    local release=""
    local grub_package="grub-efi-amd64"
    
    # Set repository URL and release based on distribution
    case $DISTRO_NAME in
        debian)
            repo_url="http://deb.debian.org/debian"
            release="stable"
            ;;
        kali)
            repo_url="http://http.kali.org/kali"
            release="kali-rolling"
            ;;
        pureos)
            repo_url="http://repo.pureos.net/pureos"
            release="byzantium"
            ;;
        *)
            warning "Unknown distribution. Cannot query repository."
            return 2
            ;;
    esac
    
    info "Querying $repo_url for $release/$grub_package..."
    
    # Create temporary sources.list for querying
    local temp_list="/tmp/installer_sources_$$.list"
    echo "deb $repo_url $release main" > "$temp_list"
    
    # Query the repository for package version
    local grub_version_info=$(apt-cache -o Dir::Etc::SourceList="$temp_list" \
        -o Dir::Etc::SourceParts="/dev/null" \
        policy "$grub_package" 2>/dev/null)
    
    if [[ -z "$grub_version_info" ]]; then
        # Fallback: try using apt-cache madison
        grub_version_info=$(apt-cache -o Dir::Etc::SourceList="$temp_list" \
            -o Dir::Etc::SourceParts="/dev/null" \
            madison "$grub_package" 2>/dev/null | head -1)
    fi
    
    # Clean up temp file
    rm -f "$temp_list"
    
    # Extract version number (e.g., 2.06-3 or 2.12-1)
    GRUB_VERSION=$(echo "$grub_version_info" | grep -oP '\d+\.\d+' | head -1)
    
    if [[ -n "$GRUB_VERSION" ]]; then
        info "Target GRUB version: $GRUB_VERSION"
        
        # Parse major and minor version
        local major=$(echo "$GRUB_VERSION" | cut -d. -f1)
        local minor=$(echo "$GRUB_VERSION" | cut -d. -f2)
        
        if [[ $major -gt 2 ]] || [[ $major -eq 2 && $minor -ge 14 ]]; then
            info "✓ Full LUKS2 support with Argon2id (GRUB 2.14+)"
            return 0
        elif [[ $major -eq 2 && $minor -ge 6 ]]; then
            info "⚠ LUKS2 support with PBKDF2 only (GRUB 2.06-2.13)"
            return 1
        else
            warning "LUKS2 not supported. GRUB version < 2.06"
            return 2
        fi
    else
        warning "Could not determine target GRUB version from repository."
        warning "This may be due to network issues or repository unavailability."
        info "Defaulting to LUKS1 for safety."
        return 2
    fi
}

# Check required packages
check_dependencies() {
    log "Checking required packages..."
    local missing_packages=()
    
    local required_packages=(
        "cryptsetup"
        "lvm2"
        "debootstrap"
        "grub-efi-amd64"
        "grub-efi-amd64-bin"
        "efibootmgr"
        "sbsigntool"
        "efitools"
        "openssl"
        "parted"
        "rsync"
        "mokutil"
        "fscrypt"
        "rsync"
    )
    
    for pkg in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            missing_packages+=("$pkg")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        warning "Missing packages: ${missing_packages[*]}"
        read -p "Do you want to install missing packages? (y/n), default (y): " install_deps
        install_deps=${install_deps:-y}
        if [[ "$install_deps" == "y" ]]; then
            apt-get update
            apt-get install -y "${missing_packages[@]}"
        else
            error "Required packages are missing. Exiting."
            exit 1
        fi
    fi
    
    log "All required packages are installed"
}

# Interactive disk selection with numbered menu
select_disk() {
    log "Available disks:"
    
    # Build arrays of disk names and display lines
    # Use NAME,SIZE,TYPE for the disk filter (avoids awk column-count issues with
    # MODEL strings that contain spaces), then fetch the full display line separately.
    local disk_names=()
    local disk_lines=()
    local name line
    while IFS= read -r name; do
        line=$(lsblk -d -n -o NAME,SIZE,TYPE,MODEL "/dev/${name}" 2>/dev/null || true)
        disk_names+=("$name")
        disk_lines+=("$line")
    done < <(lsblk -d -n -o NAME,TYPE | awk '$2=="disk"{print $1}')
    
    if [[ ${#disk_names[@]} -eq 0 ]]; then
        error "No disks found. Exiting."
        exit 1
    fi
    
    local i
    for (( i=0; i<${#disk_names[@]}; i++ )); do
        echo "  $((i+1))) ${disk_lines[$i]}"
    done
    echo ""
    
    local choice
    while true; do
        read -rp "Enter disk number (1-${#disk_names[@]}): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && \
           [[ "$choice" -ge 1 ]] && \
           [[ "$choice" -le ${#disk_names[@]} ]]; then
            TARGET_DISK="/dev/${disk_names[$((choice-1))]}"
            if [[ -b "$TARGET_DISK" ]]; then
                break
            else
                error "Device $TARGET_DISK not found. Please try again."
            fi
        else
            error "Invalid choice. Enter a number between 1 and ${#disk_names[@]}."
        fi
    done
    
    warning "WARNING: All data on $TARGET_DISK will be destroyed!"
    read -rp "Are you sure you want to continue? Type 'YES' to confirm: " confirm
    
    if [[ "$confirm" != "YES" ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
}

# Get installation parameters
get_installation_params() {
    log "Gathering installation parameters..."
    
    read -p "Enter hostname: " HOSTNAME
    read -p "Enter username: " USERNAME
    
    # Detect RAM and recommend swap size
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    local recommended_swap
    
    # Swap size recommendations based on RAM:
    # < 2GB RAM: 2x RAM
    # 2-8GB RAM: = RAM
    # > 8GB RAM: 4-8GB (for hibernation support)
    if [[ $total_ram_mb -lt 2048 ]]; then
        recommended_swap=$((total_ram_mb * 2))
    elif [[ $total_ram_mb -lt 8192 ]]; then
        recommended_swap=$total_ram_mb
    else
        # For systems with > 8GB RAM, recommend 8GB for hibernation
        recommended_swap=8192
    fi
    
    info "Detected RAM: ${total_ram_mb}MB"
    read -p "Enter swap size in MB (recommended: ${recommended_swap}, default: ${recommended_swap}): " SWAP_SIZE
    SWAP_SIZE=${SWAP_SIZE:-$recommended_swap}
    
    # Timezone configuration
    echo ""
    info "Timezone configuration"
    info "Common timezones:"
    info "  1) UTC - Coordinated Universal Time"
    info "  2) Europe/Paris - Central European Time"
    info "  3) Europe/London - British Time"
    info "  4) Europe/Berlin - Central European Time"
    info "  5) America/New_York - Eastern Time (US)"
    info "  6) America/Los_Angeles - Pacific Time (US)"
    info "  7) America/Chicago - Central Time (US)"
    info "  8) Asia/Tokyo - Japan Standard Time"
    info "  9) Asia/Shanghai - China Standard Time"
    info "  10) Australia/Sydney - Australian Eastern Time"
    info "  0) Custom - Enter manually"
    echo ""
    read -p "Enter timezone choice (0-10, default: 1): " tz_choice
    tz_choice=${tz_choice:-1}
    
    case $tz_choice in
        1)
            TIMEZONE="UTC"
            ;;
        2)
            TIMEZONE="Europe/Paris"
            ;;
        3)
            TIMEZONE="Europe/London"
            ;;
        4)
            TIMEZONE="Europe/Berlin"
            ;;
        5)
            TIMEZONE="America/New_York"
            ;;
        6)
            TIMEZONE="America/Los_Angeles"
            ;;
        7)
            TIMEZONE="America/Chicago"
            ;;
        8)
            TIMEZONE="Asia/Tokyo"
            ;;
        9)
            TIMEZONE="Asia/Shanghai"
            ;;
        10)
            TIMEZONE="Australia/Sydney"
            ;;
        0)
            read -p "Enter custom timezone (e.g., America/Toronto): " TIMEZONE
            TIMEZONE=${TIMEZONE:-UTC}
            ;;
        *)
            warning "Invalid choice, using UTC"
            TIMEZONE="UTC"
            ;;
    esac
    info "Selected timezone: $TIMEZONE"
    
    # Locale configuration
    echo ""
    info "Locale configuration"
    info "Examples: en_US.UTF-8, fr_FR.UTF-8, de_DE.UTF-8"
    read -p "Enter locale (default: fr_FR.UTF-8): " LOCALE
    LOCALE=${LOCALE:-fr_FR.UTF-8}
    
    # Keyboard layout configuration
    echo ""
    info "Keyboard layout configuration"
    info "Common layouts: us, fr, de, uk, es, it, jp"
    read -p "Enter keyboard layout (default: fr): " KEYBOARD_LAYOUT
    KEYBOARD_LAYOUT=${KEYBOARD_LAYOUT:-fr}
    read -p "Enter keyboard variant (default: empty): " KEYBOARD_VARIANT
    KEYBOARD_VARIANT=${KEYBOARD_VARIANT:-}
    
    echo ""
    info "Available distributions:"
    info "  1) debian  - Debian GNU/Linux (stable)"
    info "  2) kali    - Kali Linux (rolling)"
    info "  3) pureos  - PureOS (byzantium)"
    echo ""
    read -p "Enter distribution choice (1-3, default: 1): " DISTRO_CHOICE
    DISTRO_CHOICE=${DISTRO_CHOICE:-1}
    
    case $DISTRO_CHOICE in
        1)
            DISTRO_NAME="debian"
            ;;
        2)
            DISTRO_NAME="kali"
            ;;
        3)
            DISTRO_NAME="pureos"
            ;;
        *)
            warning "Invalid choice, defaulting to debian"
            DISTRO_NAME="debian"
            ;;
    esac

    # Set VG_NAME based on selected distribution
    VG_NAME="${DISTRO_NAME}-vg"

    # Set EFI bootloader-id per distro:
    # - Debian: shim-signed is STRICTLY locked to id 'debian' (Debian Wiki)
    # - PureOS: uses Debian's shim-signed, same strict 'debian' id required
    # - Kali:   has its own shim/EFI layout, uses 'kali'
    case $DISTRO_NAME in
        debian|pureos) EFI_BOOT_ID="debian" ;;
        kali)          EFI_BOOT_ID="kali" ;;
        *)             EFI_BOOT_ID="debian" ;;
    esac
    info "EFI bootloader-id: $EFI_BOOT_ID"

    if [[ "$DISTRO_NAME" == "kali" ]]; then
        warning "Kali: Secure Boot is NOT enabled by default."
        warning "  After installation you must disable SB, enroll the MOK key, then re-enable SB."
        warning "  The kernel signing hook will re-sign vmlinuz after every update."
    fi

    # LUKS version selection based on GRUB support
    echo ""
    set +e  # Temporarily disable exit on error to capture return code
    check_target_grub_version
    local grub_support=$?
    set -e  # Re-enable exit on error
    
    if [[ $grub_support -eq 0 ]]; then
        # Full LUKS2 support with Argon2id (GRUB 2.14+)
        info "LUKS encryption options:"
        info "  1) LUKS1 - Legacy, maximum compatibility"
        info "  2) LUKS2 + PBKDF2 - Compatible with GRUB 2.06+"
        info "  3) LUKS2 + Argon2id - Best security, requires GRUB 2.14+ (recommended)"
        echo ""
        read -p "Enter LUKS choice (1-3, default: 3): " LUKS_CHOICE
        LUKS_CHOICE=${LUKS_CHOICE:-3}
        
        case $LUKS_CHOICE in
            1)
                LUKS_VERSION="luks1"
                ;;
            2)
                LUKS_VERSION="luks2-pbkdf2"
                ;;
            3)
                LUKS_VERSION="luks2-argon2id"
                ;;
            *)
                warning "Invalid choice, using LUKS2 + Argon2id"
                LUKS_VERSION="luks2-argon2id"
                ;;
        esac
    elif [[ $grub_support -eq 1 ]]; then
        # LUKS2 with PBKDF2 only (GRUB 2.06-2.13)
        info "LUKS encryption options:"
        info "  1) LUKS1 - Legacy, maximum compatibility"
        info "  2) LUKS2 + PBKDF2 - Compatible with your GRUB version (recommended)"
        echo ""
        warning "Note: Argon2 not supported by your GRUB version (< 2.14)"
        read -p "Enter LUKS choice (1-2, default: 2): " LUKS_CHOICE
        LUKS_CHOICE=${LUKS_CHOICE:-2}
        
        case $LUKS_CHOICE in
            1)
                LUKS_VERSION="luks1"
                ;;
            2)
                LUKS_VERSION="luks2-pbkdf2"
                ;;
            *)
                warning "Invalid choice, using LUKS2 + PBKDF2"
                LUKS_VERSION="luks2-pbkdf2"
                ;;
        esac
    else
        # No LUKS2 support (GRUB < 2.06)
        warning "Your GRUB version does not support LUKS2. Using LUKS1."
        LUKS_VERSION="luks1"
    fi

    echo ""
    info "Installation Summary:"
    info "Target Disk: $TARGET_DISK"
    info "Hostname: $HOSTNAME"
    info "Username: $USERNAME"
    info "Swap Size: ${SWAP_SIZE}MB"
    info "EFI Partition Size: ${EFI_SIZE}MB"
    info "Distribution: $DISTRO_NAME"
    info "LUKS Version: $LUKS_VERSION"
    info "TPM2 Available: $TPM_AVAILABLE"
    info "Timezone: $TIMEZONE"
    info "Locale: $LOCALE"
    info "Keyboard: $KEYBOARD_LAYOUT${KEYBOARD_VARIANT:+ ($KEYBOARD_VARIANT)}"
    echo ""
    
    read -p "Proceed with installation? (y/n, default: y): " proceed
    proceed=${proceed:-y}
    if [[ "$proceed" != "y" ]]; then
        log "Installation cancelled"
        exit 0
    fi
}

# Partition disk
partition_disk() {
    log "Partitioning disk $TARGET_DISK..."
    
    # Wipe existing partition table
    wipefs -a "$TARGET_DISK"
    
    # Create GPT partition table
    parted -s "$TARGET_DISK" mklabel gpt
    
    # Create EFI partition (512MB)
    parted -s "$TARGET_DISK" mkpart primary fat32 1MiB ${EFI_SIZE}MiB
    parted -s "$TARGET_DISK" set 1 esp on
    
    # Create root partition (remaining space)
    parted -s "$TARGET_DISK" mkpart primary ${EFI_SIZE}MiB 100%
    
    # Wait for kernel to update partition table
    partprobe "$TARGET_DISK"
    sleep 2
    
    log "Partitions created successfully"
    lsblk "$TARGET_DISK"
}

# Setup LUKS encryption
setup_encryption() {
    log "Setting up LUKS encryption..."
    
    # Determine partition names (handle nvme and sd* differently)
    if [[ "$TARGET_DISK" == *"nvme"* ]]; then
        EFI_PART="${TARGET_DISK}p1"
        ROOT_PART="${TARGET_DISK}p2"
    else
        EFI_PART="${TARGET_DISK}1"
        ROOT_PART="${TARGET_DISK}2"
    fi
    
    info "Encrypting $ROOT_PART with $LUKS_VERSION..."
    
    # Capture passphrase once; reuse for luksFormat, luksOpen, luksAddKey
    local LUKS_PASS2
    while true; do
        read -rsp "Enter passphrase for disk encryption: " LUKS_PASS; echo
        read -rsp "Confirm passphrase: " LUKS_PASS2; echo
        if [[ -z "$LUKS_PASS" ]]; then
            error "Passphrase cannot be empty. Please try again."
        elif [[ "$LUKS_PASS" != "$LUKS_PASS2" ]]; then
            error "Passphrases do not match. Please try again."
        else
            unset LUKS_PASS2
            break
        fi
    done
    
    # LUKS format based on version selection
    case $LUKS_VERSION in
        luks1)
            info "Using LUKS1 with AES-XTS-256 and SHA-512"
            cryptsetup --verbose luksFormat --type luks1 \
                -c aes-xts-plain64 -s 512 -h sha512 \
                "$ROOT_PART" --key-file <(printf '%s' "$LUKS_PASS")
            ;;
        luks2-pbkdf2)
            info "Using LUKS2 with PBKDF2 (GRUB 2.04+ compatible)"
            cryptsetup --verbose luksFormat --type luks2 \
                --cipher aes-xts-plain64 --key-size 512 \
                --hash sha512 --pbkdf pbkdf2 \
                --iter-time 5000 \
                "$ROOT_PART" --key-file <(printf '%s' "$LUKS_PASS")
            ;;
        luks2-argon2id)
            info "Using LUKS2 with Argon2id (best security, GRUB 2.12+ required)"
            cryptsetup --verbose luksFormat --type luks2 \
                --cipher aes-xts-plain64 --key-size 512 \
                --hash sha512 --pbkdf argon2id \
                --iter-time 2000 --pbkdf-memory 1048576 \
                "$ROOT_PART" --key-file <(printf '%s' "$LUKS_PASS")
            ;;
        *)
            error "Unknown LUKS version: $LUKS_VERSION"
            exit 1
            ;;
    esac
    
    # Open encrypted partition
    cryptsetup luksOpen "$ROOT_PART" "${ROOT_PART##*/}_crypt" \
        --key-file <(printf '%s' "$LUKS_PASS")
    
    # Display LUKS header info
    info "LUKS header information:"
    cryptsetup luksDump "$ROOT_PART" | grep -E "(Version|Cipher|Hash|PBKDF)"
    
    log "Encryption setup complete"
}

# Setup LVM
setup_lvm() {
    log "Setting up LVM..."
    
    local crypt_device="/dev/mapper/${ROOT_PART##*/}_crypt"
    
    # Create physical volume
    pvcreate "$crypt_device"
    
    # Create volume group
    vgcreate "$VG_NAME" "$crypt_device"
    
    # Create swap logical volume
    lvcreate -L "${SWAP_SIZE}M" -n swap "$VG_NAME"
    
    # Get free extents
    local free_extents=$(vgdisplay "$VG_NAME" | grep "Free  PE" | awk '{print $5}')
    info "Free extents available: $free_extents"
    
    # Create root logical volume with all remaining space
    lvcreate -l "$free_extents" -n root "$VG_NAME"
    
    # Activate volume group
    vgchange -a y "$VG_NAME"
    
    log "LVM setup complete"
}

# Format partitions
format_partitions() {
    log "Formatting partitions..."
    
    # Format EFI partition
    mkfs.fat -F32 "$EFI_PART"
    
    # Format swap
    mkswap "/dev/mapper/${VG_NAME//-/--}-swap"
    
    # Format root
    mkfs.ext4 "/dev/mapper/${VG_NAME//-/--}-root"
    
    log "Partitions formatted successfully"
}

# Mount partitions
mount_partitions() {
    log "Mounting partitions..."
    
    mkdir -p "$MOUNT_POINT"
    mount "/dev/mapper/${VG_NAME//-/--}-root" "$MOUNT_POINT"
    
    mkdir -p "${MOUNT_POINT}/boot/efi"
    mount "$EFI_PART" "${MOUNT_POINT}/boot/efi"
    
    log "Partitions mounted"
}

# Install base system
install_base_system() {
    log "Installing base system..."
    
    # Essential packages for encrypted LVM system
    # For Kali, we install minimal base first, then add packages via apt
    local essential_packages="cryptsetup,cryptsetup-initramfs,lvm2,initramfs-tools,linux-image-amd64,firmware-linux-free,busybox"
    
    read -p "Enter path to ${DISTRO_NAME} ISO file (or press Enter to use network): " iso_path
    
    if [[ -n "$iso_path" && -f "$iso_path" ]]; then
        # Install from ISO
        mkdir -p "$ISO_MOUNT"
        mount -o loop "$iso_path" "$ISO_MOUNT"
        
        log "Installing base system..."
        case $DISTRO_NAME in
            debian)
                debootstrap --arch=amd64 --include="$essential_packages" stable "$MOUNT_POINT" "file://${ISO_MOUNT}"
                ;;
            kali)
                # Kali: Use minbase variant and install packages later to avoid debootstrap conflicts
                debootstrap --arch=amd64 --variant=minbase kali-rolling "$MOUNT_POINT" "file://${ISO_MOUNT}"
                ;;
            pureos)
                debootstrap --arch=amd64 --include="$essential_packages" byzantium "$MOUNT_POINT" "file://${ISO_MOUNT}"
                ;;
        esac
        
        umount "$ISO_MOUNT"
    else
        # Install from network
        warning "Installing from network. This may take a while..."
        case $DISTRO_NAME in
            debian)
                debootstrap --arch=amd64 --include="$essential_packages" stable "$MOUNT_POINT" http://deb.debian.org/debian/
                ;;
            kali)
                # Kali: Use minbase variant and install packages later to avoid debootstrap conflicts
                debootstrap --arch=amd64 --variant=minbase kali-rolling "$MOUNT_POINT" http://http.kali.org/kali
                ;;
            pureos)
                debootstrap --arch=amd64 --include="$essential_packages" byzantium "$MOUNT_POINT" http://repo.pureos.net/pureos
                ;;
        esac
    fi
    
    # For Kali, install essential packages after base system
    if [[ "$DISTRO_NAME" == "kali" ]]; then
        log "Installing essential packages for Kali..."
        cat > "${MOUNT_POINT}/etc/apt/sources.list" <<EOF
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
EOF
        
        # Mount necessary filesystems for chroot
        mount --bind /dev "${MOUNT_POINT}/dev"
        mount --bind /dev/pts "${MOUNT_POINT}/dev/pts"
        mount --bind /proc "${MOUNT_POINT}/proc"
        mount --bind /sys "${MOUNT_POINT}/sys"
        
        # Install essential packages via apt in chroot
        chroot "$MOUNT_POINT" /bin/bash -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            # Install kali-archive-keyring first to fix signature verification
            apt-get install -y --allow-unauthenticated kali-archive-keyring
            apt-get update
            apt-get install -y cryptsetup cryptsetup-initramfs lvm2 initramfs-tools linux-image-amd64 firmware-linux-free busybox dialog whiptail apt-utils
        "
        
        # Unmount filesystems
        umount "${MOUNT_POINT}/sys"
        umount "${MOUNT_POINT}/proc"
        umount "${MOUNT_POINT}/dev/pts"
        umount "${MOUNT_POINT}/dev"
    fi
    
    # Configure APT sources (skip for Kali as already configured above)
    if [[ "$DISTRO_NAME" != "kali" ]]; then
        log "Configuring APT sources..."
        case $DISTRO_NAME in
            debian)
                cat > "${MOUNT_POINT}/etc/apt/sources.list" <<EOF
deb http://deb.debian.org/debian/ stable main contrib non-free-firmware
deb-src http://deb.debian.org/debian/ stable main contrib non-free-firmware

deb http://security.debian.org/debian-security stable-security main contrib non-free-firmware
deb-src http://security.debian.org/debian-security stable-security main contrib non-free-firmware

deb http://deb.debian.org/debian/ stable-updates main contrib non-free-firmware
deb-src http://deb.debian.org/debian/ stable-updates main contrib non-free-firmware
EOF
                ;;
            pureos)
                cat > "${MOUNT_POINT}/etc/apt/sources.list" <<EOF
deb http://repo.pureos.net/pureos byzantium main
deb http://repo.pureos.net/pureos byzantium-security main
deb http://repo.pureos.net/pureos byzantium-updates main
EOF
                ;;
        esac
    fi
    
    log "Base system installed"
}

# Configure system files
configure_system() {
    log "Configuring system files..."
    
    # Get UUIDs
    local root_part_uuid=$(blkid -s UUID -o value "$ROOT_PART")
    local efi_part_uuid=$(blkid -s UUID -o value "$EFI_PART")
    
#     # Configure crypttab (passphrase-based unlocking)
#     log "Configuring /etc/crypttab..."
#     cat > "${MOUNT_POINT}/etc/crypttab" <<EOF
# ${ROOT_PART##*/}_crypt UUID=${root_part_uuid} none luks
# EOF

    # Create keys directory for keyfile
    log "Creating keyfile for automatic decryption..."
    mkdir -p "${MOUNT_POINT}${KEYS_LOCATION}"
    
    # Generate random keyfile (4096 bytes)
    # dd if=/dev/urandom of="${MOUNT_POINT}${KEYS_LOCATION}/initram_key.keyfile" bs=4096 count=1
    dd bs=512 count=4 if=/dev/random iflag=fullblock | install -m 0600 /dev/stdin ${MOUNT_POINT}${KEYS_LOCATION}/initram_key.keyfile
    
    # Add keyfile to LUKS slot 1 (slot 0 is the passphrase)
    # Authenticate with the passphrase captured during setup_encryption()
    info "Adding keyfile to LUKS volume (slot 1)..."
    cryptsetup luksAddKey "$ROOT_PART" "${MOUNT_POINT}${KEYS_LOCATION}/initram_key.keyfile" \
        --key-slot 1 --key-file <(printf '%s' "$LUKS_PASS")

    # Passphrase no longer needed — clear from memory
    unset LUKS_PASS
    
    # Verify the key slot
    local key_slot=1
    # Check for both LUKS1 format ("Key Slot 1: ENABLED") and LUKS2 format ("  1: luks2")
    if cryptsetup luksDump "$ROOT_PART" | grep -qE "(Key Slot 1: ENABLED|^  1: luks2)"; then
        log "Keyfile successfully added to slot 1"
    else
        error "Failed to add keyfile to slot 1"
        exit 1
    fi
    
    # Configure crypttab with keyfile
    log "Configuring /etc/crypttab..."
    # Note: Use 'luks' option for both LUKS1 and LUKS2
    # cryptsetup auto-detects the LUKS version from the partition header
    cat > "${MOUNT_POINT}/etc/crypttab" <<EOF
# <target name> <source device>         <key file>      <options>
${ROOT_PART##*/}_crypt UUID=${root_part_uuid} ${KEYS_LOCATION}/initram_key.keyfile luks,key-slot=${key_slot}
EOF

    #  Configure /etc/cryptsetup-initramfs/conf-hook to include keyfile
    log "Configuring initramfs to include keyfile..."
    mkdir -p "${MOUNT_POINT}/etc/cryptsetup-initramfs"
    cat > "${MOUNT_POINT}/etc/cryptsetup-initramfs/conf-hook" <<EOF
# Include keyfile in initramfs
KEYFILE_PATTERN="${KEYS_LOCATION}/*.keyfile"
CRYPTSETUP=y
EOF

    # Set umask to 0077 for security
    log "Setting secure umask for initramfs..."
    echo "UMASK=0077" >> "${MOUNT_POINT}/etc/initramfs-tools/initramfs.conf"

    # Configure fstab
    log "Configuring /etc/fstab..."
    cat > "${MOUNT_POINT}/etc/fstab" <<EOF
# <file system> <mount point> <type> <options> <dump> <pass>
/dev/mapper/${VG_NAME//-/--}-root /               ext4    errors=remount-ro 0       1
UUID=${efi_part_uuid}       /boot/efi       vfat    umask=0077        0       1
/dev/mapper/${VG_NAME//-/--}-swap none            swap    sw                0       0
EOF
    
    # Configure hostname
    echo "$HOSTNAME" > "${MOUNT_POINT}/etc/hostname"
    
    # Configure timezone
    log "Configuring timezone: $TIMEZONE..."
    ln -sf "/usr/share/zoneinfo/${TIMEZONE}" "${MOUNT_POINT}/etc/localtime"
    echo "$TIMEZONE" > "${MOUNT_POINT}/etc/timezone"
    
    # Configure locale
    log "Configuring locale: $LOCALE..."
    echo "$LOCALE UTF-8" > "${MOUNT_POINT}/etc/locale.gen"
    echo "en_US.UTF-8 UTF-8" >> "${MOUNT_POINT}/etc/locale.gen"  # Always include en_US
    
    cat > "${MOUNT_POINT}/etc/default/locale" <<EOF
LANG=$LOCALE
LANGUAGE=${LOCALE%%.*}
LC_ALL=$LOCALE
EOF
    
    # Configure keyboard layout
    log "Configuring keyboard layout: $KEYBOARD_LAYOUT..."
    cat > "${MOUNT_POINT}/etc/default/keyboard" <<EOF
# KEYBOARD CONFIGURATION FILE

# Consult the keyboard(5) manual page.

XKBMODEL="pc105"
XKBLAYOUT="$KEYBOARD_LAYOUT"
XKBVARIANT="$KEYBOARD_VARIANT"
XKBOPTIONS=""

BACKSPACE="guess"
EOF
    
    # Configure hosts
    cat > "${MOUNT_POINT}/etc/hosts" <<EOF
127.0.0.1       localhost
127.0.1.1       ${HOSTNAME}

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF
    
    # Configure resume for hibernation
    log "Configuring resume for hibernation..."
    mkdir -p "${MOUNT_POINT}/etc/initramfs-tools/conf.d"
    local swap_uuid=$(blkid -s UUID -o value "/dev/mapper/${VG_NAME//-/--}-swap")
    echo "RESUME=UUID=${swap_uuid}" > "${MOUNT_POINT}/etc/initramfs-tools/conf.d/resume"

    # Ensure cryptsetup is included in initramfs
    log "Configuring initramfs for cryptsetup..."
    cat > "${MOUNT_POINT}/etc/initramfs-tools/conf.d/cryptsetup" <<'EOF'
# Enable cryptsetup in initramfs
CRYPTSETUP=y
EOF
    
    log "System configuration complete"
}

# Chroot and configure GRUB
configure_grub() {
    log "Configuring GRUB..."
    
    # Mount necessary filesystems for chroot
    mount -t proc none "${MOUNT_POINT}/proc"
    mount -t sysfs none "${MOUNT_POINT}/sys"
    mount --bind /dev "${MOUNT_POINT}/dev"
    mount --bind /dev/pts "${MOUNT_POINT}/dev/pts"
    
    # Configure GRUB settings
    local swap_uuid=$(blkid -s UUID -o value "/dev/mapper/${VG_NAME//-/--}-swap")
    
    # Set GRUB distributor based on selected distro
    local grub_distributor
    case $DISTRO_NAME in
        debian) grub_distributor="Debian" ;;
        kali)   grub_distributor="Kali" ;;
        pureos) grub_distributor="PureOS" ;;
        *)      grub_distributor="Debian" ;;
    esac
    
    cat >> "${MOUNT_POINT}/etc/default/grub" <<EOF

# Cryptodisk configuration
GRUB_DEFAULT=0 
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_DISTRIBUTOR=${grub_distributor}
GRUB_CMDLINE_LINUX=""
GRUB_PRELOAD_MODULES="part_gpt part_msdos cryptodisk luks lvm"
GRUB_ENABLE_CRYPTODISK="y"
GRUB_SAVEDEFAULT="false"
GRUB_TERMINAL_INPUT="console"
GRUB_CMDLINE_LINUX_DEFAULT="quiet resume=UUID=${swap_uuid} init_on_free=1"
EOF
    
    # Add kernel parameters for encrypted root
    local root_part_uuid=$(blkid -s UUID -o value "$ROOT_PART")
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=${root_part_uuid}:${ROOT_PART##*/}_crypt root=/dev/mapper/${VG_NAME//-/--}-root\"|" \
        "${MOUNT_POINT}/etc/default/grub"
    
    # Create chroot script with USERNAME passed
    cat > "${MOUNT_POINT}/tmp/configure_grub.sh" <<CHROOT_EOF
#!/bin/bash
set -e

# Set USERNAME for GRUB password
USERNAME="${USERNAME}"
DISTRO_NAME="${DISTRO_NAME}"

# Install required packages
apt-get update

# Distro-specific GRUB packages
if [[ "\$DISTRO_NAME" == "debian" ]]; then
    # Debian has signed GRUB packages
    apt-get install -y grub-efi-amd64 grub-efi-amd64-signed shim-signed cryptsetup lvm2 \
        linux-image-amd64 linux-headers-amd64 sbsigntool efitools openssl \
        locales console-setup keyboard-configuration tzdata fscrypt libpam-fscrypt \
        xdg-user-dirs secure-delete zstd rsync
else
    # Kali and PureOS don't have grub-efi-amd64-signed or shim-signed packages
    # We'll use unsigned GRUB and sign it ourselves with custom Secure Boot keys
    apt-get install -y grub-efi-amd64 cryptsetup lvm2 \
        linux-image-amd64 linux-headers-amd64 sbsigntool efitools openssl \
        locales console-setup keyboard-configuration tzdata fscrypt libpam-fscrypt \
        xdg-user-dirs secure-delete zstd rsync
fi

# Install essential system packages for functional OS
echo ""
echo "Installing essential system packages..."

# Base packages common to all distributions
apt-get install -y \
    systemd-sysv \
    network-manager \
    network-manager-gnome \
    alsa-utils \
    bluez \
    bluez-tools \
    bluetooth \
    ufw \
    tasksel \
    dbus \
    sudo \
    wget \
    curl \
    vim \
    nano \
    htop \
    git \
    bash-completion

# Distro-specific packages
if [[ "\$DISTRO_NAME" == "pureos" ]]; then
    # PureOS is fully free - no non-free firmware, uses PulseAudio instead of Pipewire
    echo "Installing PureOS-specific packages..."
    apt-get install -y pulseaudio pulseaudio-utils pavucontrol
elif [[ "\$DISTRO_NAME" == "debian" ]]; then
    # Debian with firmware and Pipewire
    echo "Installing Debian-specific packages..."
    apt-get install -y \
        firmware-linux \
        firmware-linux-nonfree \
        pipewire \
        pipewire-pulse \
        wireplumber \
        pulseaudio-utils \
        pavucontrol
elif [[ "\$DISTRO_NAME" == "kali" ]]; then
    # Kali with firmware and Pipewire
    echo "Installing Kali-specific packages..."
    apt-get install -y \
        firmware-linux \
        firmware-linux-nonfree \
        pipewire \
        pipewire-pulse \
        wireplumber \
        pulseaudio-utils \
        pavucontrol
fi

echo "Essential packages installed successfully"

# Generate locales now that locales package is installed
echo ""
echo "Generating locales..."
locale-gen

# Configure hardware clock to UTC
dpkg-reconfigure -f noninteractive tzdata

# Apply keyboard configuration
setupcon --save

# Ensure EFI directory exists for this distribution
mkdir -p /boot/efi/EFI/${EFI_BOOT_ID}

# Install GRUB
# Note: bootloader-id is distro-specific:
#   Debian/PureOS: STRICTLY 'debian' (shim-signed locks path to /EFI/debian/)
#   Kali:          'kali'
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=${EFI_BOOT_ID} --recheck

# Configure GRUB password protection
echo ""
echo "========================================"
echo "GRUB Password Protection Setup"
echo "========================================"
echo "You will now set a password for the GRUB bootloader."
echo "This password protects against editing boot entries."
echo ""

# Read password with confirmation
while true; do
    echo "Enter GRUB password for '\${USERNAME}' user:"
    read -s GRUB_PASS1
    echo ""
    echo "Confirm GRUB password:"
    read -s GRUB_PASS2
    echo ""
    
    if [ "\$GRUB_PASS1" = "\$GRUB_PASS2" ]; then
        if [ -z "\$GRUB_PASS1" ]; then
            echo "Error: Password cannot be empty. Please try again."
            echo ""
        else
            echo "✓ Passwords match. Generating secure hash..."
            break
        fi
    else
        echo "Error: Passwords do not match. Please try again."
        echo ""
    fi
done

# Generate password hash
GRUB_PASSWORD_HASH=\$(echo -e "\$GRUB_PASS1\n\$GRUB_PASS1" | grub-mkpasswd-pbkdf2 | grep -oP 'grub\\.pbkdf2\\.sha512\\.\\S+')

# Clear password variables
unset GRUB_PASS1
unset GRUB_PASS2

# Add password configuration to 40_custom
cat >> /etc/grub.d/40_custom <<GRUBPASS_EOF

# GRUB password protection
set superusers="\${USERNAME}"
password_pbkdf2 \${USERNAME} \${GRUB_PASSWORD_HASH}
GRUBPASS_EOF

echo "GRUB password configured successfully"

# Make boot menu entries unrestricted (password only for editing/GRUB shell)
# This allows booting the default entry without requiring GRUB username/password.
# Patching the template ensures this survives kernel updates / grub-mkconfig reruns.
echo "Configuring unrestricted boot for menu entries..."
sed -i 's/^CLASS="--class gnu-linux /CLASS="--class gnu-linux --unrestricted /' /etc/grub.d/10_linux

# Generate GRUB config (entries are already --unrestricted from the patched template)
grub-mkconfig -o /boot/grub/grub.cfg

# Verify cryptodisk module is loaded
if ! grep -q "insmod cryptodisk" /boot/grub/grub.cfg; then
    echo "WARNING: cryptodisk module not found in grub.cfg"
fi

# Update initramfs
update-initramfs -u -k all

# Verify keyfile inclusion in initramfs
echo ""
echo "Verifying keyfile inclusion in initramfs..."
INITRAMFS_IMG=\$(ls -1 /boot/initrd.img-* | head -n1)
if [ -n "\$INITRAMFS_IMG" ]; then
    echo "Checking initramfs: \$INITRAMFS_IMG"
    
    # Check permissions
    PERMS=\$(stat -c "%a" "\$INITRAMFS_IMG")
    echo "Initramfs permissions: \$PERMS"
    if [ "\$PERMS" = "600" ] || [ "\$PERMS" = "400" ]; then
        echo "✓ Initramfs has restrictive permissions"
    else
        echo "⚠ WARNING: Initramfs permissions are not restrictive enough"
    fi
    
    # Check for keyfile
    if lsinitramfs "\$INITRAMFS_IMG" | grep -q "etc/sb_keys/initram_key.keyfile"; then
        echo "✓ Keyfile found in initramfs"
    else
        echo "⚠ WARNING: Keyfile NOT found in initramfs"
    fi
else
    echo "⚠ WARNING: Could not find initramfs to verify"
fi
echo ""

echo "GRUB configuration complete"

# Enable essential services
echo ""
echo "Enabling essential services..."
systemctl enable NetworkManager
systemctl enable bluetooth
systemctl enable ufw

# Configure firewall
echo "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

echo "Services configured successfully"

# Optional desktop environment installation
echo ""
echo "========================================"
echo "Desktop Environment Installation"
echo "========================================"
echo "Would you like to install a desktop environment?"
echo ""
read -p "Install desktop environment? (y/n), default: (y): " install_de
install_de=${install_de:-y}
if [[ "\$install_de" == "y" ]]; then
    # For Kali, use kali-desktop-xfce by default
    if [[ "\$DISTRO_NAME" == "kali" ]]; then
        echo "Installing Kali XFCE desktop environment..."
        apt-get install -y kali-desktop-xfce
        systemctl set-default graphical.target
        echo "Kali XFCE desktop installed successfully"
    else
        echo ""
        echo "Available desktop environments:"
        echo "  1) GNOME - Full-featured desktop (recommended)"
        echo "  2) KDE Plasma - Highly customizable"
        echo "  3) XFCE - Lightweight and fast"
        echo "  4) LXDE - Extremely lightweight"
        echo "  5) MATE - Traditional desktop"
        echo "  6) Cinnamon - Modern and elegant"
        echo "  7) Custom tasksel selection"
        echo ""
        read -p "Enter choice (1-7, 0 to skip): " de_choice
        
        case \$de_choice in
            1)
                echo "Installing GNOME desktop..."
                tasksel install gnome-desktop --new-install
                systemctl set-default graphical.target
                ;;
            2)
                echo "Installing KDE Plasma desktop..."
                tasksel install kde-desktop --new-install
                systemctl set-default graphical.target
                ;;
            3)
                echo "Installing XFCE desktop..."
                tasksel install xfce-desktop --new-install
                systemctl set-default graphical.target
                ;;
            4)
                echo "Installing LXDE desktop..."
                tasksel install lxde-desktop --new-install
                systemctl set-default graphical.target
                ;;
            5)
                echo "Installing MATE desktop..."
                tasksel install mate-desktop --new-install
                systemctl set-default graphical.target
                ;;
            6)
                echo "Installing Cinnamon desktop..."
                apt-get install -y cinnamon-desktop-environment
                systemctl set-default graphical.target
                ;;
            7)
                echo "Running tasksel for custom selection..."
                tasksel
                ;;
            0)
                echo "Skipping desktop environment installation"
                ;;
            *)
                echo "Invalid choice, skipping desktop environment"
                ;;
        esac
        
        if [[ \$de_choice -ge 1 && \$de_choice -le 7 ]]; then
            echo "Desktop environment installed successfully"
        fi
    fi
fi

# Install macchanger by default for MAC address randomization
echo ""
echo "Installing macchanger for MAC address privacy..."
apt-get install -y macchanger
echo "macchanger installed successfully"

# Software profile installation
echo ""
echo "=========================================="
echo "Software Profile Installation"
echo "=========================================="
echo "Select a software profile to install:"
echo ""
echo "  1) Office + Media - Productivity and multimedia tools"
echo "     (LibreOffice, Chromium, Thunderbird, Media players, etc.)"
echo ""
echo "  2) Developer - Full development environment"
echo "     (Includes Office + Media + VSCode, Docker, Git, IDEs, etc.)"
echo ""
echo "  0) Skip - No additional software"
echo ""
read -p "Enter choice (0-2): " profile_choice

case \$profile_choice in
    1)
        echo ""
        echo "Installing Office + Media profile..."
        # Base packages available on all distributions
        apt-get install -y \\
            libreoffice libreoffice-gtk3 \\
            thunar thunar-archive-plugin thunar-media-tags-plugin \\
            smplayer smplayer-themes smplayer \\
            chromium \\
            transmission transmission-gtk \\
            uget \\
            thunderbird \\
            gnome-tweaks \\
            blueman \\
            bleachbit \\
            syncthing syncthing-gtk \\
            xfce4-clipman xfce4-clipman-plugin \\
            gufw \\
            rhythmbox rhythmbox-plugins \\
            remmina remmina-plugin-rdp remmina-plugin-vnc \\
            synaptic \\
            gparted \\
            onionshare \\
            diffpdf \\
            # pdfmod \\
            # pdfsam \\
            # pika-backup \\
            shortwave \\
            || echo "Some packages may not be available in repository"
        
        # Additional packages not available on PureOS
        if [[ "\$DISTRO_NAME" != "pureos" ]]; then
            apt-get install -y hardinfo2 fsearch torbrowser-launcher || true
        fi

        # Additional packages for PureOS
        if [[ "\$DISTRO_NAME" == "pureos" ]]; then
            apt-get install -y hardinfo tor || true
        fi
        
        echo "Office + Media profile installed successfully"
        ;;
    2)
        echo ""
        echo "Installing Developer profile (includes Office + Media)..."
        
        # Install Office + Media packages first (base packages available on all distributions)
        apt-get install -y \\
            libreoffice libreoffice-gtk3 \\
            thunar thunar-archive-plugin thunar-media-tags-plugin \\
            smplayer smplayer-themes smplayer \\
            chromium \\
            transmission transmission-gtk \\
            uget \\
            thunderbird \\
            gnome-tweaks \\
            blueman \\
            bleachbit \\
            syncthing syncthing-gtk \\
            xfce4-clipman xfce4-clipman-plugin \\
            gufw \\
            rhythmbox rhythmbox-plugins \\
            remmina remmina-plugin-rdp remmina-plugin-vnc \\
            synaptic \\
            gparted \\
            onionshare \\
            diffpdf \\
            # pdfmod \\
            # pdfsam \\
            # pika-backup \\
            shortwave \\
            || echo "Some Office + Media packages may not be available"
        
        # Additional packages not available on PureOS
        if [[ "\$DISTRO_NAME" != "pureos" ]]; then
            apt-get install -y hardinfo2 fsearch torbrowser-launcher || true
        fi
        
        # Additional packages for PureOS
        if [[ "\$DISTRO_NAME" == "pureos" ]]; then
            apt-get install -y hardinfo tor || true
        fi
        
        # Install developer tools
        echo "Installing development tools..."
        apt-get install -y \\
            flameshot \\
            git git-lfs \\
            build-essential \\
            nodejs npm \\
            docker.io docker-compose \\
            virt-manager qemu-kvm libvirt-daemon-system \\
            kdenlive \\
            gimp gimp-data-extras \\
            inkscape \\
            obs-studio \\
            filezilla \\
            gtkhash \\
            meld \\
            curl wget \\
            python3-pip \\
            default-jdk \\
            cmake \\
            blender \\
            || echo "Some developer packages may not be available"
        
        # Enable and start Docker
        systemctl enable docker
        systemctl enable libvirtd
        
        # Add user to docker and libvirt groups (will take effect after reboot)
        usermod -aG docker ${USERNAME} || true
        usermod -aG libvirt ${USERNAME} || true
        
        # Install yarn globally via npm
        npm install -g yarn || echo "Yarn installation failed"
        
        echo "Developer profile installed successfully"
        ;;
    0)
        echo "Skipping additional software installation"
        ;;
    *)
        echo "Invalid choice, skipping additional software"
        ;;
esac

# Install additional software from external sources
if [[ \$profile_choice -ge 1 ]]; then
    echo ""
    echo "=========================================="
    echo "Installing Additional Software from External Sources"
    echo "=========================================="
    
    # Create temporary directory for downloads
    TEMP_DEB="/tmp/deb_downloads"
    mkdir -p "\$TEMP_DEB"
    cd "\$TEMP_DEB"
    
    # Install VS Code (Developer profile only)
    if [[ \$profile_choice -eq 2 ]]; then
        echo "Installing Visual Studio Code..."
        wget -q https://packages.microsoft.com/keys/microsoft.asc -O- | gpg --dearmor > microsoft.gpg
        install -o root -g root -m 644 microsoft.gpg /etc/apt/trusted.gpg.d/
        echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list
        apt-get update
        apt-get install -y code || echo "VS Code installation failed"
    fi
    
    # Install Spotify (both profiles)
    echo "Installing Spotify..."
    curl -sS https://download.spotify.com/debian/pubkey_5384CE82BA52C83A.asc | sudo gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/spotify.gpg
    echo "deb https://repository.spotify.com stable non-free" | sudo tee /etc/apt/sources.list.d/spotify.list
    apt-get update
    apt-get install -y spotify-client || echo "Spotify installation failed"
    
    # Install DBeaver (Developer profile only)
    if [[ \$profile_choice -eq 2 ]]; then
        echo "Installing DBeaver Community Edition..."
        wget -q https://dbeaver.io/files/dbeaver-ce_latest_amd64.deb
        dpkg -i dbeaver-ce_latest_amd64.deb || apt-get install -f -y
    fi
    
    # Install Postman (Developer profile only)
    if [[ \$profile_choice -eq 2 ]]; then
        echo "Installing Postman..."
        wget -q https://dl.pstmn.io/download/latest/linux64 -O postman.tar.gz
        tar -xzf postman.tar.gz -C /opt/
        ln -sf /opt/Postman/Postman /usr/local/bin/postman
        
        # Create desktop entry
        cat > /usr/share/applications/postman.desktop <<POSTMAN_EOF
[Desktop Entry]
Name=Postman
Comment=API Development Environment
Exec=/opt/Postman/Postman
Icon=/opt/Postman/app/resources/app/assets/icon.png
Terminal=false
Type=Application
Categories=Development;
POSTMAN_EOF
    fi
    
    # Install LocalSend (both profiles)
    echo "Installing LocalSend..."
    LOCALSEND_VERSION=\$(curl -s https://api.github.com/repos/localsend/localsend/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    if [ -n "\$LOCALSEND_VERSION" ]; then
        wget -q "https://github.com/localsend/localsend/releases/download/\${LOCALSEND_VERSION}/LocalSend-\${LOCALSEND_VERSION#v}-linux-x86-64.deb" -O localsend.deb
        dpkg -i localsend.deb || apt-get install -f -y
    else
        echo "Could not determine LocalSend latest version"
    fi
    
    # Install Logseq (both profiles)
    echo "Installing Logseq..."
    LOGSEQ_VERSION=\$(curl -s https://api.github.com/repos/logseq/logseq/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    if [ -n "\$LOGSEQ_VERSION" ]; then
        wget -q "https://github.com/logseq/logseq/releases/download/\${LOGSEQ_VERSION}/Logseq-linux-x64-\${LOGSEQ_VERSION}.AppImage" -O /opt/logseq.AppImage
        chmod +x /opt/logseq.AppImage
        
        # Create desktop entry
        cat > /usr/share/applications/logseq.desktop <<LOGSEQ_EOF
[Desktop Entry]
Name=Logseq
Comment=A privacy-first, open-source knowledge base
Exec=/opt/logseq.AppImage --no-sandbox
Icon=logseq
Terminal=false
Type=Application
Categories=Office;Utility;
LOGSEQ_EOF
    else
        echo "Could not determine Logseq latest version"
    fi
    
    # Install Exodus (both profiles) - Bitcoin/crypto wallet
    # echo "Installing Exodus wallet..."
    # wget -q "https://downloads.exodus.com/releases/exodus-linux-x64-26.3.11.deb" -O exodus.deb
    # dpkg -i exodus.deb || apt-get install -f -y
    
    # Cleanup
    cd /
    rm -rf "\$TEMP_DEB"
    
    echo "Additional software installation complete"
    echo "Note: Some packages (GalaxyBuds, Kiro, Antigravity, Scangear2) may require"
    echo "      manual installation or may not be available for Linux."
fi

CHROOT_EOF
    
    chmod +x "${MOUNT_POINT}/tmp/configure_grub.sh"
    chroot "$MOUNT_POINT" /tmp/configure_grub.sh
    
    # Unmount chroot filesystems
    umount "${MOUNT_POINT}/dev/pts"
    umount "${MOUNT_POINT}/dev"
    umount "${MOUNT_POINT}/sys"
    umount "${MOUNT_POINT}/proc"
    
    # Create EFI boot entry manually (in case chroot grub-install didn't work)
    log "Creating EFI boot entry..."
    if [[ "$TARGET_DISK" == *"nvme"* ]]; then
        DISK_NUM="${TARGET_DISK##*nvme}"
        DISK_NUM="${DISK_NUM%%p*}"
    else
        DISK_NUM="${TARGET_DISK##*[a-z]}"
    fi
    
    # Create boot entry with efibootmgr (path matches the distro-specific EFI_BOOT_ID)
    local boot_label="${DISTRO_NAME^}"  # Capitalize first letter
    efibootmgr -c -d "$TARGET_DISK" -p 1 -L "$boot_label" -l "\\EFI\\${EFI_BOOT_ID}\\grubx64.efi" || \
        warning "Failed to create EFI boot entry. You may need to boot manually."
    
    log "GRUB configuration complete"
}

# Setup Secure Boot
setup_secure_boot() {
    log "Setting up UEFI Secure Boot..."
    
    # Create keys directory
    mkdir -p "${MOUNT_POINT}${KEYS_LOCATION}"
    
    info "Generating Secure Boot keys..."
    
    # Generate keys
    cd "${MOUNT_POINT}${KEYS_LOCATION}"
    
    # PK (Platform Key)
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=EFI PK/" \
        -keyout PK.key -out PK.crt -days 36500 -nodes -sha256
    
    # KEK (Key Exchange Key)
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=EFI KEK/" \
        -keyout KEK.key -out KEK.crt -days 36500 -nodes -sha256
    
    # db (Signature Database)
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=EFI db/" \
        -keyout db.key -out db.crt -days 36500 -nodes -sha256
    
    # Convert to DER format for kernel module signing
    openssl x509 -in db.crt -outform DER -out db.der
    
    # Convert certificates to EFI signature lists
    cert-to-efi-sig-list PK.crt PK.esl
    cert-to-efi-sig-list KEK.crt KEK.esl
    cert-to-efi-sig-list db.crt db.esl
    
    # Sign the signature lists
    sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth
    sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth
    sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth
    
    cd -
    
    log "Secure Boot keys generated"
    
    # Generate signed GRUB binary
    generate_signed_grub
    
    warning "Secure Boot keys have been generated but NOT enrolled yet."
    warning "Keys are located in: ${KEYS_LOCATION}"
    echo ""
    
}

# Generate and sign GRUB binary
generate_signed_grub() {
    log "Generating signed GRUB binary..."
    
    # Mount filesystems for chroot
    mount -t proc none "${MOUNT_POINT}/proc"
    mount -t sysfs none "${MOUNT_POINT}/sys"
    mount --bind /dev "${MOUNT_POINT}/dev"
    
    # Create script to generate GRUB standalone binary.
    # Use a two-step heredoc: unquoted header injects EFI_BOOT_ID from outer scope;
    # single-quoted body keeps $GRUB_MODULES/$KEYS_LOCATION as runtime variables.
    cat > "${MOUNT_POINT}/tmp/generate_grub.sh" <<GRUB_GEN_HEADER
#!/bin/bash
set -e
# EFI_BOOT_ID injected at install time (debian/kali/pureos-specific path)
EFI_BOOT_ID="${EFI_BOOT_ID}"
GRUB_GEN_HEADER
    cat >> "${MOUNT_POINT}/tmp/generate_grub.sh" <<'GRUB_GEN_EOF'

KEYS_LOCATION="/etc/sb_keys"
GRUB_MODULES="tpm all_video archelp boot bufio configfile crypto echo efi_gop efi_uga extcmd fat font fshelp gcry_dsa gcry_rsa gcry_sha1 gettext gfxterm linux ls memdisk minicmd mmap mpi normal password_pbkdf2 pbkdf2 reboot relocator search search_fs_file search_fs_uuid search_label sleep tar terminal video_fb part_gpt part_msdos cryptodisk luks gcry_rijndael lvm ext2 gcry_sha512 test gzio luks2 gcry_sha256"

# Ensure EFI directory exists
mkdir -p "/boot/efi/EFI/${EFI_BOOT_ID}"
# Cleanup old EFI files
rm -f /boot/efi/EFI/${EFI_BOOT_ID}/*

# Generate standalone GRUB binary
grub-mkstandalone \
    -d /usr/lib/grub/x86_64-efi/ \
    -O x86_64-efi \
    --modules="$GRUB_MODULES" \
    --fonts="unicode" \
    --disable-shim-lock \
    -o "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi" \
    "boot/grub/grub.cfg=/boot/grub/grub.cfg"

# Sign the binary
sbsign --key "${KEYS_LOCATION}/db.key" \
    --cert "${KEYS_LOCATION}/db.crt" \
    "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi" \
    --output "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64.efi"

# Clean up temporary file
rm "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi"

echo "Signed GRUB binary generated"

# Sign NVIDIA kernel modules if available
# DKMS-built NVIDIA modules must be signed with custom Secure Boot keys;
# distro-provided NVIDIA signing keys are not trusted in our custom db.
inst_kern=$(uname -r)
SIGN_FILE="/usr/src/linux-headers-${inst_kern}/scripts/sign-file"
if [[ -x "${SIGN_FILE}" && -f "${KEYS_LOCATION}/db.der" ]]; then
    echo "Checking for NVIDIA kernel modules to sign..."
    nvidia_signed=0
    for mod in nvidia nvidia-modeset nvidia-uvm nvidia-drm nvidia-peermem; do
        mod_path=$(modinfo -k "${inst_kern}" -n "${mod}" 2>/dev/null || true)
        if [[ -n "${mod_path}" && -f "${mod_path}" ]]; then
            echo "Signing NVIDIA module: ${mod_path}..."
            "${SIGN_FILE}" sha256 "${KEYS_LOCATION}/db.key" "${KEYS_LOCATION}/db.der" "${mod_path}"
            echo "✓ Signed: ${mod_path}"
            nvidia_signed=$((nvidia_signed + 1))
        fi
    done
    if [[ "${nvidia_signed}" -gt 0 ]]; then
        echo "✓ ${nvidia_signed} NVIDIA module(s) signed successfully"
    else
        echo "INFO: No NVIDIA modules found for kernel ${inst_kern}, skipping"
    fi
else
    if [[ ! -x "${SIGN_FILE}" ]]; then
        echo "INFO: sign-file not found at ${SIGN_FILE}, skipping NVIDIA module signing"
    fi
    if [[ ! -f "${KEYS_LOCATION}/db.der" ]]; then
        echo "WARNING: ${KEYS_LOCATION}/db.der not found, cannot sign NVIDIA modules" >&2
    fi
fi
GRUB_GEN_EOF
    
    chmod +x "${MOUNT_POINT}/tmp/generate_grub.sh"
    chroot "$MOUNT_POINT" /tmp/generate_grub.sh
    
    # Unmount
    umount "${MOUNT_POINT}/dev"
    umount "${MOUNT_POINT}/sys"
    umount "${MOUNT_POINT}/proc"
    
    # Sign the kernel images with custom Secure Boot keys
    log "Signing kernel images..."
    for kernel in "${MOUNT_POINT}"/boot/vmlinuz-*; do
        if [[ -f "$kernel" ]]; then
            log "Signing $(basename "$kernel")..."
            sbsign --key "${MOUNT_POINT}${KEYS_LOCATION}/db.key" \
                   --cert "${MOUNT_POINT}${KEYS_LOCATION}/db.crt" \
                   "$kernel" \
                   --output "${kernel}.signed"
            mv "${kernel}.signed" "$kernel"
        fi
    done
    log "Kernel images signed"
    
    log "Signed GRUB binary created"
}

# Install kernel hooks for automatic signing
install_kernel_hooks() {
    log "Installing kernel update hooks..."
    
    # Create postinst hook.
    # Two-step heredoc: unquoted header embeds EFI_BOOT_ID and DISTRO_NAME at install time;
    # single-quoted body keeps $GRUB_MODULES/$KEYS_LOCATION as runtime variables.
    cat > "${MOUNT_POINT}/etc/kernel/postinst.d/zz-sign-grub" <<HOOK_HEADER
#!/bin/bash
set -e
# Values embedded at install time
EFI_BOOT_ID="${EFI_BOOT_ID}"
DISTRO_NAME="${DISTRO_NAME}"
HOOK_HEADER
    cat >> "${MOUNT_POINT}/etc/kernel/postinst.d/zz-sign-grub" <<'HOOK_EOF'

inst_kern=$1

if [ -z "$inst_kern" ]; then
    inst_kern=$(uname -r)
fi

KEYS_LOCATION="/etc/sb_keys"
GRUB_MODULES="tpm all_video archelp boot bufio configfile crypto echo efi_gop efi_uga extcmd fat font fshelp gcry_dsa gcry_rsa gcry_sha1 gettext gfxterm linux ls memdisk minicmd mmap mpi normal password_pbkdf2 pbkdf2 reboot relocator search search_fs_file search_fs_uuid search_label sleep tar terminal video_fb part_gpt part_msdos cryptodisk luks gcry_rijndael lvm ext2 gcry_sha512 test gzio luks2 gcry_sha256"

echo "Cleaning up old EFI files..."
# Remove /BOOT directory (fallback boot path)
rm -rf /boot/efi/EFI/BOOT

# Clean up distro-specific EFI directory
rm -f /boot/efi/EFI/${EFI_BOOT_ID}/*

echo "Generating new GRUB binary..."

# Generate standalone GRUB binary
grub-mkstandalone \
    -d /usr/lib/grub/x86_64-efi/ \
    -O x86_64-efi \
    --modules="$GRUB_MODULES" \
    --fonts="unicode" \
    --disable-shim-lock \
    -o "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi" \
    "boot/grub/grub.cfg=/boot/grub/grub.cfg"

echo "Signing GRUB binary..."

# Sign the binary
sbsign --key "${KEYS_LOCATION}/db.key" \
    --cert "${KEYS_LOCATION}/db.crt" \
    "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi" \
    --output "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64.efi"

# Clean up
rm "/boot/efi/EFI/${EFI_BOOT_ID}/grubx64_generated.efi"

echo "GRUB binary signed successfully"

# Sign kernel images with custom Secure Boot keys
# All kernels (Debian/Kali/PureOS) need to be signed with custom keys
# because distro-signed kernels use keys that are not in our custom db
VMLINUZ="/boot/vmlinuz-${inst_kern}"
if [[ -f "${VMLINUZ}" ]]; then
    echo "Signing kernel image ${VMLINUZ}..."
    sbsign --key "${KEYS_LOCATION}/db.key" \
           --cert "${KEYS_LOCATION}/db.crt" \
           "${VMLINUZ}" \
           --output "${VMLINUZ}.signed"
    mv "${VMLINUZ}.signed" "${VMLINUZ}"
    echo "✓ Kernel image signed: ${VMLINUZ}"
else
    echo "WARNING: kernel image not found at ${VMLINUZ}" >&2
fi

# Sign NVIDIA kernel modules if available
# DKMS-built NVIDIA modules must be signed with custom Secure Boot keys;
# distro-provided NVIDIA signing keys are not trusted in our custom db.
SIGN_FILE="/usr/src/linux-headers-${inst_kern}/scripts/sign-file"
if [[ -x "${SIGN_FILE}" && -f "${KEYS_LOCATION}/db.der" ]]; then
    echo "Checking for NVIDIA kernel modules to sign..."
    nvidia_signed=0
    for mod in nvidia nvidia-modeset nvidia-uvm nvidia-drm nvidia-peermem; do
        mod_path=$(modinfo -k "${inst_kern}" -n "${mod}" 2>/dev/null || true)
        if [[ -n "${mod_path}" && -f "${mod_path}" ]]; then
            echo "Signing NVIDIA module: ${mod_path}..."
            "${SIGN_FILE}" sha256 "${KEYS_LOCATION}/db.key" "${KEYS_LOCATION}/db.der" "${mod_path}"
            echo "✓ Signed: ${mod_path}"
            nvidia_signed=$((nvidia_signed + 1))
        fi
    done
    if [[ "${nvidia_signed}" -gt 0 ]]; then
        echo "✓ ${nvidia_signed} NVIDIA module(s) signed successfully"
    else
        echo "INFO: No NVIDIA modules found for kernel ${inst_kern}, skipping"
    fi
else
    if [[ ! -x "${SIGN_FILE}" ]]; then
        echo "INFO: sign-file not found at ${SIGN_FILE}, skipping NVIDIA module signing"
    fi
    if [[ ! -f "${KEYS_LOCATION}/db.der" ]]; then
        echo "WARNING: ${KEYS_LOCATION}/db.der not found, cannot sign NVIDIA modules" >&2
    fi
fi

exit 0
HOOK_EOF
    
    chmod +x "${MOUNT_POINT}/etc/kernel/postinst.d/zz-sign-grub"
    
    # Create postrm hook
    cp "${MOUNT_POINT}/etc/kernel/postinst.d/zz-sign-grub" \
        "${MOUNT_POINT}/etc/kernel/postrm.d/zz-sign-grub"
    
    log "Kernel hooks installed"
}

# Create user account
create_user() {
    log "Creating user account with encrypted home directory..."
    
    mount -t proc none "${MOUNT_POINT}/proc"
    mount -t sysfs none "${MOUNT_POINT}/sys"
    mount --bind /dev "${MOUNT_POINT}/dev"
    
    # Write first-login-message.sh separately with a quoted heredoc so that
    # $variables and $(commands) are preserved literally (not expanded by the
    # outer shell).  The chroot script copies it into the user's home later.
    cat > "${MOUNT_POINT}/tmp/first-login-message.sh" <<'FIRSTLOGIN_EOF'
#!/bin/bash
# First login message - shows important security information once
# Presents a dialog with next steps and a button to enroll Secure Boot keys

KEYS_LOCATION="/etc/sb_keys"

enroll_secure_boot_keys() {
    # Run all three efi-updatevar commands in a single pkexec call
    # so the user is only prompted for a password once.
    local log=""
    local failed=0

    enroll_output=$(pkexec bash -c '
        failed=0
        for cmd in \
            "efi-updatevar -f '"${KEYS_LOCATION}"'/db.auth db" \
            "efi-updatevar -f '"${KEYS_LOCATION}"'/KEK.auth KEK" \
            "efi-updatevar -f '"${KEYS_LOCATION}"'/PK.auth PK"; do
            echo "CMD:${cmd}"
            output=$(eval "${cmd}" 2>&1)
            rc=$?
            echo "RC:${rc}"
            echo "OUT:${output}"
            if [ $rc -ne 0 ]; then failed=1; fi
        done
        echo "CMD:lsattr /sys/firmware/efi/efivars/db-*"
        verify=$(lsattr /sys/firmware/efi/efivars/db-* 2>&1)
        echo "RC:0"
        echo "OUT:${verify}"
        exit $failed
    ' 2>&1)
    failed=$?

    # Parse the structured output into a readable log
    local current_cmd=""
    while IFS= read -r line; do
        case "$line" in
            CMD:*) current_cmd="${line#CMD:}"; log+="$ ${current_cmd}\n" ;;
            RC:0)  ;;
            RC:*)  log+="ERROR (exit ${line#RC:})\n" ;;
            OUT:)  log+="OK\n\n" ;;
            OUT:*) log+="${line#OUT:}\n\n" ;;
        esac
    done <<< "$enroll_output"

    if [ "$failed" -eq 0 ]; then
        summary="✅ All Secure Boot keys enrolled successfully!"
    else
        summary="⚠️ Some commands failed. You may not be in Setup Mode.\n\nMake sure you:\n1. Disabled Secure Boot in UEFI settings\n2. Cleared/deleted all Secure Boot keys\n3. Rebooted into this system\n\nThen try again."
    fi

    if command -v zenity &>/dev/null; then
        zenity --text-info --width=700 --height=400 \
            --title="Secure Boot Key Enrollment Result" \
            --filename=<(echo -e "${summary}\n\n── Command Log ──\n${log}")
    else
        echo -e "${summary}\n\n── Command Log ──\n${log}"
        read -p "Press Enter to continue..."
    fi

    return $failed
}

MESSAGE_STEP1="<b>Step 1 — Backup Important dirs</b>

  Encryption metadata: <tt>sudo cp -a /.fscrypt YOUR_BACKUP_LOCATION</tt>
  Secure Boot keys: <tt>sudo cp -a ${KEYS_LOCATION} YOUR_BACKUP_LOCATION</tt>"

MESSAGE_STEP2="<b>Step 2 — Enroll custom Secure Boot keys</b>

  Click <b>\"Enroll Keys Now\"</b> below, or run manually:
    <tt>sudo efi-updatevar -f ${KEYS_LOCATION}/db.auth db</tt>
    <tt>sudo efi-updatevar -f ${KEYS_LOCATION}/KEK.auth KEK</tt>
    <tt>sudo efi-updatevar -f ${KEYS_LOCATION}/PK.auth PK</tt>

  ⚠ This removes ALL vendor keys (Microsoft, OEM) — other OS/hardware may break.
  After enrolling, re-enable Secure Boot in UEFI settings."

MESSAGE_STEP3="<b>Step 3 — Verify</b>

  Secure Boot will now trust your signed GRUB.
  Reboot and confirm Secure Boot is active by running mokutil --sb-state"

PLAIN_MESSAGE="Installation Complete!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 IMPORTANT NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Backup /.fscrypt for later recovery
   sudo cp -a /.fscrypt YOUR_BACKUP_LOCATION
   Backup Secure Boot keys: sudo cp -a ${KEYS_LOCATION} YOUR_BACKUP_LOCATION

2. Boot into UEFI firmware settings and:
   - Enter Setup Mode (disable SB, clear keys, reboot)
   - Enroll custom keys:
       sudo efi-updatevar -f ${KEYS_LOCATION}/db.auth db
       sudo efi-updatevar -f ${KEYS_LOCATION}/KEK.auth KEK
       sudo efi-updatevar -f ${KEYS_LOCATION}/PK.auth PK
   - Re-enable Secure Boot

3. Secure Boot will now trust your signed GRUB. Reboot and confirm Secure Boot is active by running mokutil --sb-state"

show_zenity_dialog() {
    while true; do
        FULL_TEXT="<big><b>Installation Complete!</b></big>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 IMPORTANT NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${MESSAGE_STEP1}

${MESSAGE_STEP2}

${MESSAGE_STEP3}"

        zenity --question --width=700 --title="System Security Setup Complete" \
            --text="$FULL_TEXT" \
            --ok-label="Enroll Keys Now" \
            --cancel-label="Close"
        EXIT_CODE=$?

        if [ "$EXIT_CODE" -eq 0 ]; then
            # "Enroll Keys Now" clicked
            if enroll_secure_boot_keys; then
                break
            fi
        else
            # "Close" clicked
            break
        fi
    done
}

show_kdialog_dialog() {
    kdialog --msgbox "$PLAIN_MESSAGE\n\nTo enroll Secure Boot keys, select 'Enroll Keys Now'." \
        --title "System Security Setup Complete"

    if kdialog --yesno "Would you like to enroll Secure Boot keys now?\n\nThis will run:\n  sudo efi-updatevar -f ${KEYS_LOCATION}/db.auth db\n  sudo efi-updatevar -f ${KEYS_LOCATION}/KEK.auth KEK\n  sudo efi-updatevar -f ${KEYS_LOCATION}/PK.auth PK\n\n⚠ Make sure you are in UEFI Setup Mode first!" \
        --title "Enroll Secure Boot Keys"; then
        enroll_secure_boot_keys
    fi
}

show_terminal_dialog() {
    echo ""
    echo "$PLAIN_MESSAGE"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Options:"
    echo "  [1] Enroll Secure Boot keys now (Step 2)"
    echo "  [q] Close"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    while true; do
        read -p "Enter choice [1/q]: " choice
        case "$choice" in
            1)
                enroll_secure_boot_keys
                ;;
            q|Q)
                break
                ;;
            *)
                echo "Invalid choice."
                ;;
        esac
    done
}

# Main: pick the best available UI
# Copy the log from /var/log/ to user home dir
LOG_FILE=$(ls -1t /var/log/debian-secure-installer_*.log 2>/dev/null | head -n1)
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    cp "$LOG_FILE" "$HOME/" 2>/dev/null && \
    chown $(id -u):$(id -g) "$HOME/$(basename "$LOG_FILE")" 2>/dev/null && \
    chmod 644 "$HOME/$(basename "$LOG_FILE")" 2>/dev/null
fi

if command -v zenity &>/dev/null; then
    show_zenity_dialog
elif command -v kdialog &>/dev/null; then
    show_kdialog_dialog
else
    show_terminal_dialog
fi

# Remove this script after first run
rm -f ~/.config/autostart/first-login-message.desktop
rm -f ~/.local/bin/first-login-message.sh
FIRSTLOGIN_EOF

    cat > "${MOUNT_POINT}/tmp/create_user.sh" <<USEREOF
#!/bin/bash
set -e

# Security hardening for fscrypt login protectors
echo ""
echo "======================================="
echo "Security Hardening for fscrypt"
echo "======================================="
echo "Configuring strong passphrase hashing and sudo timeout..."
echo ""

# Configure sudo timeout to reduce frequency of password entry
echo "Configuring sudo timeout (60 minutes)..."
if ! grep -q "Defaults timestamp_timeout=60" /etc/sudoers 2>/dev/null; then
    echo "Defaults timestamp_timeout=60" >> /etc/sudoers
    echo "  ✓ Sudo timeout set to 60 minutes"
else
    echo "  ✓ Sudo timeout already configured"
fi

# Strengthen PAM password hashing to ~1 million rounds
# This makes offline attacks on /etc/shadow significantly harder
echo "Strengthening password hashing (1,000,000 rounds)..."
if [ -f /etc/pam.d/passwd ]; then
    # Check if rounds is already configured
    if ! grep -q "rounds=" /etc/pam.d/passwd 2>/dev/null; then
        if grep -q "pam_unix.so" /etc/pam.d/passwd 2>/dev/null; then
            # Append rounds=1000000 to the existing pam_unix.so line
            sed -i 's/\(password.*pam_unix.so.*\)/\1 rounds=1000000/' /etc/pam.d/passwd
        else
            # pam_unix.so line absent — insert the complete line
            printf 'password\trequired\tpam_unix.so sha512 shadow nullok rounds=1000000\n' >> /etc/pam.d/passwd
        fi
        echo "  ✓ PAM password hashing set to 1,000,000 rounds (~1 second)"
    else
        echo "  ✓ PAM password hashing already configured"
    fi
else
    echo "  ⚠ WARNING: /etc/pam.d/passwd not found"
fi

echo ""
echo "Security hardening complete."
echo "Your login passphrase will now be hashed with strong parameters."
echo "This protects against offline attacks on /.fscrypt metadata."
echo ""

# Create /etc/pam.d/fscrypt for fscrypt login passphrase checking
echo "Configuring /etc/pam.d/fscrypt..."
if [ ! -f /etc/pam.d/fscrypt ]; then
    cat > /etc/pam.d/fscrypt <<'FSCRYPT_PAM_EOF'
auth required pam_unix.so
FSCRYPT_PAM_EOF
    echo "  ✓ /etc/pam.d/fscrypt created"
else
    echo "  ✓ /etc/pam.d/fscrypt already exists"
fi
echo ""

# Set passwords first
echo "======================================="
echo "Password Configuration"
echo "======================================="
echo "You will now set passwords for root and user accounts."
echo "IMPORTANT: Use strong, unique passphrases (12+ characters recommended)."
echo ""

# Configure root user environment
echo "Configuring root user environment..."
if [ ! -f /root/.bashrc ] || ! grep -q "bash-completion" /root/.bashrc 2>/dev/null; then
    cat >> /root/.bashrc <<'ROOT_BASHRC_EOF'

# Enable bash completion
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
ROOT_BASHRC_EOF
    echo "  ✓ Root bash-completion configured"
fi

echo ""
echo "Set password for root:"
passwd root

echo ""
echo "======================================"
echo "User Account with Encrypted Home Setup"
echo "======================================"
echo "Creating user $USERNAME with fscrypt encrypted home directory."
echo "You will need to set the user password."
echo ""

# Create user WITHOUT creating home directory yet
useradd -M -s /bin/bash -G sudo,audio,video,netdev "$USERNAME"

# Set user password
echo "Set password for $USERNAME:"
passwd "$USERNAME"

# Setup fscrypt encrypted home
echo ""
echo "Setting up encrypted home directory for $USERNAME..."

# Enable ext4 encryption on root partition
echo "Enabling ext4 encryption feature..."
ROOT_DEVICE=\$(findmnt -n -o SOURCE /)
tune2fs -O encrypt \$ROOT_DEVICE

# Initialize fscrypt
echo "Initializing fscrypt..."
fscrypt setup
# Note: fscrypt setup already configures the root filesystem /

# Create temporary backup directory
TEMP_HOME="/home/${USERNAME}.tmp"
mkdir -p "\$TEMP_HOME"

# Copy skeleton files to temporary location
echo "Preparing home directory structure..."
if [ -d /etc/skel ]; then
    cp -rT /etc/skel "\$TEMP_HOME"
fi

# Ensure essential dot files exist and configure them properly
# Configure .profile with proper PATH
cat > "\$TEMP_HOME/.profile" <<'PROFILE_EOF'
# ~/.profile: executed by the command interpreter for login shells.

# Set PATH to include system directories
if [ -n "\$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "\$HOME/.bashrc" ]; then
        . "\$HOME/.bashrc"
    fi
fi

# Set PATH so it includes /sbin and /usr/sbin
if [ -d "/sbin" ] ; then
    PATH="/sbin:\$PATH"
fi
if [ -d "/usr/sbin" ] ; then
    PATH="/usr/sbin:\$PATH"
fi
if [ -d "/usr/local/sbin" ] ; then
    PATH="/usr/local/sbin:\$PATH"
fi

# Set PATH for user's private bin if it exists
if [ -d "\$HOME/bin" ] ; then
    PATH="\$HOME/bin:\$PATH"
fi
if [ -d "\$HOME/.local/bin" ] ; then
    PATH="\$HOME/.local/bin:\$PATH"
fi

export PATH
PROFILE_EOF

# Configure .bashrc with bash-completion
cat > "\$TEMP_HOME/.bashrc" <<'BASHRC_EOF'
# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
      *) return;;
esac

# History settings
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s histappend

# Check window size after each command
shopt -s checkwinsize

# Make less more friendly for non-text input files
[ -x /usr/bin/lesspipe ] && eval "\$(SHELL=/bin/sh lesspipe)"

# Set variable identifying the chroot you work in
if [ -z "\${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=\$(cat /etc/debian_chroot)
fi

# Set a fancy prompt (non-color, unless we know we "want" color)
case "\$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ "\$color_prompt" = yes ]; then
    PS1='\${debian_chroot:+(\$debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='\${debian_chroot:+(\$debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt

# Enable color support for ls and add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "\$(dircolors -b ~/.dircolors)" || eval "\$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# Some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Alias definitions
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# Enable programmable completion features
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

# Add /sbin and /usr/sbin to PATH for non-root users
if [ "\$(id -u)" -ne 0 ]; then
    export PATH="/usr/local/sbin:/usr/sbin:/sbin:\$PATH"
fi
BASHRC_EOF

touch "\$TEMP_HOME/.bash_logout"

# Create standard XDG user directories
echo "Creating default user directories..."
mkdir -p "\$TEMP_HOME"/{Desktop,Documents,Downloads,Music,Pictures,Public,Templates,Videos}

# Create common hidden directories
mkdir -p "\$TEMP_HOME/.config/autostart"
mkdir -p "\$TEMP_HOME/.local/share"
mkdir -p "\$TEMP_HOME/.local/bin"

# Create encrypted home directory
echo "Creating encrypted home directory..."
mkdir -p /home/${USERNAME}

# Configure PAM for fscrypt automatic unlocking
echo ""
echo "Configuring PAM for automatic home directory unlocking..."

# Auth hook - for unlocking at login
if ! grep -q "pam_fscrypt.so" /etc/pam.d/common-auth 2>/dev/null; then
    echo "auth    optional    pam_fscrypt.so" >> /etc/pam.d/common-auth
    echo "  ✓ Auth hook added to /etc/pam.d/common-auth"
else
    echo "  ✓ Auth hook already present in /etc/pam.d/common-auth"
fi

# Session hook - for locking at logout
if ! grep -q "pam_fscrypt.so" /etc/pam.d/common-session 2>/dev/null; then
    echo "session optional    pam_fscrypt.so" >> /etc/pam.d/common-session
    echo "  ✓ Session hook added to /etc/pam.d/common-session"
else
    echo "  ✓ Session hook already present in /etc/pam.d/common-session"
fi

# Password hook - for rewrapping protector on password change
if ! grep -q "pam_fscrypt.so" /etc/pam.d/common-password 2>/dev/null; then
    echo "password    optional    pam_fscrypt.so" >> /etc/pam.d/common-password
    echo "  ✓ Password hook added to /etc/pam.d/common-password"
else
    echo "  ✓ Password hook already present in /etc/pam.d/common-password"
fi

echo "PAM configuration complete"
echo ""

# Create first-login message script
echo "Creating first-login welcome message..."

cp /tmp/first-login-message.sh "\$TEMP_HOME/.local/bin/first-login-message.sh"
chmod +x "\$TEMP_HOME/.local/bin/first-login-message.sh"

# Create autostart desktop entry
cat > "\$TEMP_HOME/.config/autostart/first-login-message.desktop" <<'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Name=First Login Security Message
Exec=/home/${USERNAME}/.local/bin/first-login-message.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
AUTOSTART_EOF

echo "✓ First-login welcome message configured"

# Encrypt the home directory and link to login password (must be done while empty)
echo ""
echo "Encrypting home directory (linked to login password)..."
echo "Choose 1 - Your login passphrase (pam_passphrase) to link encryption to your login password"
fscrypt encrypt /home/${USERNAME} --user=${USERNAME}

# Copy files to encrypted directory
echo "Copying files to encrypted home directory..."
rsync -a "\$TEMP_HOME/" /home/${USERNAME}/

# Set ownership and permissions after copying
chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}
chmod 700 /home/${USERNAME}
chmod 755 /home/${USERNAME}/{Desktop,Documents,Downloads,Music,Pictures,Public,Templates,Videos}

# Update user's home directory in passwd
usermod -d /home/${USERNAME} ${USERNAME}

# Initialize XDG user directories
echo "Initializing XDG user directories..."
su - ${USERNAME} -c "xdg-user-dirs-update" 2>/dev/null || true

# Securely remove temporary directory
echo "Cleaning up temporary files..."
srm -rfll "\$TEMP_HOME" 2>/dev/null || rm -rf "\$TEMP_HOME"

# Verify encryption status
echo ""
echo "Verifying encryption..."
fscrypt status /home/${USERNAME}
if ! fscrypt status /home/${USERNAME} 2>/dev/null | grep -q "Encrypted: true\|is encrypted with fscrypt"; then
    echo "ERROR: /home/${USERNAME} does not appear to be encrypted!"
    echo "fscrypt encrypt may have failed. Please check manually."
    exit 1
fi

echo ""
echo "✓ Encrypted home directory configured for $USERNAME"
echo "  The home directory will be automatically unlocked on login."
echo "✓ Default directories created: Desktop, Documents, Downloads, Music,"
echo "  Pictures, Public, Templates, Videos"
echo "✓ Skeleton files copied from /etc/skel"
echo "✓ Encryption: fscrypt (ext4 native encryption)"
echo ""

USEREOF
    
    chmod +x "${MOUNT_POINT}/tmp/create_user.sh"
    chroot "$MOUNT_POINT" /tmp/create_user.sh
    
    umount "${MOUNT_POINT}/dev"
    umount "${MOUNT_POINT}/sys"
    umount "${MOUNT_POINT}/proc"
    
    log "User account created with encrypted home directory"
    info "The user's home directory is protected with fscrypt (ext4 native encryption)"
    info "It will be automatically unlocked on login via PAM integration"
    info "Default directories and skeleton files have been installed"
}



# Configure cold boot attack mitigation via kernel init_on_free
configure_ram_swiper() {
    log "Configuring cold boot attack mitigation (init_on_free)..."
    
    # init_on_free=1 is set in GRUB_CMDLINE_LINUX_DEFAULT during configure_grub.
    # The kernel zeros every memory page as it is freed — this covers:
    #   - Process exit (encryption keys wiped immediately when process ends)
    #   - Shutdown/reboot (all remaining pages freed and zeroed by kernel)
    # Benefits over userspace sdmem:
    #   - No OOM risk (kernel-native, no userspace allocation)
    #   - Instant at shutdown (pages already zeroed during normal operation)
    #   - More thorough (covers all frees, not just a single sweep at shutdown)
    # Trade-off: ~1-2% runtime overhead (acceptable for a security-focused system)
    
    # init_on_free requires kernel >= 5.3 (introduced Sep 2019)
    # All supported distros (Debian 11+/Kali/PureOS Byzantium) ship 5.10+
    local target_kernel
    target_kernel=$(ls "${MOUNT_POINT}/boot/vmlinuz-"* 2>/dev/null | sort -V | tail -n1 | grep -oP '\d+\.\d+')
    if [[ -n "$target_kernel" ]]; then
        local kmajor kminor
        kmajor=$(echo "$target_kernel" | cut -d. -f1)
        kminor=$(echo "$target_kernel" | cut -d. -f2)
        if (( kmajor < 5 || (kmajor == 5 && kminor < 3) )); then
            warning "Target kernel ${target_kernel} is < 5.3 — init_on_free=1 not supported"
            warning "Cold boot mitigation will NOT be active. Consider upgrading the kernel."
            return 0
        fi
        log "Target kernel ${target_kernel} supports init_on_free=1"
    else
        warning "Could not detect target kernel version — assuming init_on_free=1 is supported"
    fi
    
    # Verify the parameter is present in GRUB config
    if grep -q "init_on_free=1" "${MOUNT_POINT}/etc/default/grub" 2>/dev/null; then
        log "init_on_free=1 confirmed in GRUB kernel command line"
    else
        warning "init_on_free=1 not found in GRUB config — adding it now"
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="init_on_free=1 /' \
            "${MOUNT_POINT}/etc/default/grub"
    fi
    
    log "Cold boot mitigation configured (kernel init_on_free=1)"
    info "The kernel will zero all memory pages on free — no sdmem needed"
    info "This mitigates cold boot attacks by clearing encryption keys from memory"
}

# Final cleanup
cleanup() {
    log "Performing cleanup..."

    # Sync filesystems
    sync

    # Unmount chroot filesystems if still mounted
    if mountpoint -q "${MOUNT_POINT}/dev/pts" 2>/dev/null; then
        umount "${MOUNT_POINT}/dev/pts" 2>/dev/null || true
    fi
    if mountpoint -q "${MOUNT_POINT}/dev" 2>/dev/null; then
        umount "${MOUNT_POINT}/dev" 2>/dev/null || true
    fi
    if mountpoint -q "${MOUNT_POINT}/sys" 2>/dev/null; then
        umount "${MOUNT_POINT}/sys" 2>/dev/null || true
    fi
    if mountpoint -q "${MOUNT_POINT}/proc" 2>/dev/null; then
        umount "${MOUNT_POINT}/proc" 2>/dev/null || true
    fi
    
    # Unmount EFI partition
    if mountpoint -q "${MOUNT_POINT}/boot/efi" 2>/dev/null; then
        umount "${MOUNT_POINT}/boot/efi" 2>/dev/null || true
    fi
    
    # Unmount root partition
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || true
    fi
    
    # Deactivate LVM volumes if they exist
    if [[ -n "$VG_NAME" ]]; then
        if vgs "$VG_NAME" &>/dev/null; then
            log "Deactivating LVM volume group: $VG_NAME"
            vgchange -a n "$VG_NAME" 2>/dev/null || true
        fi
    fi
    
    # Close LUKS devices
    if [[ -n "$ROOT_PART" ]]; then
        local crypt_name="${ROOT_PART##*/}_crypt"
        if [[ -e "/dev/mapper/$crypt_name" ]]; then
            log "Closing LUKS device: $crypt_name"
            cryptsetup luksClose "$crypt_name" 2>/dev/null || true
        fi
    fi
    
    # Additional cleanup for any stray device mapper devices related to target disk
    if [[ -n "$TARGET_DISK" ]]; then
        local disk_name="${TARGET_DISK##*/}"
        for dm in /dev/mapper/*; do
            if [[ "$dm" =~ $disk_name ]]; then
                dmsetup remove "$dm" 2>/dev/null || true
            fi
        done
    fi
    
    log "Cleanup complete"
}

# Main installation flow
main() {
    # Setup logging - redirect all output to both console and log file
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    clear
    log "=========================================="
    log "Debian-based Secure Installer"
    log "Full Disk Encryption + UEFI Secure Boot"
    log "Supports: Debian, Kali Linux, PureOS"
    log "LUKS1/LUKS2 with auto GRUB detection"
    log "fscrypt encrypted /home directories (ext4 native encryption)"
    log "NetworkManager, Audio, Bluetooth, Firewall"
    log "Optional Desktop Environment installation"
    log "TPM detection and GRUB measured boot support"
    log "=========================================="
    echo ""
    info "Installation log: $LOG_FILE"
    echo ""

    check_root
    check_uefi
    check_secure_boot
    check_tpm_support
    check_dependencies
    
    select_disk
    get_installation_params
    
    partition_disk
    setup_encryption
    setup_lvm
    format_partitions
    mount_partitions
    
    install_base_system
    configure_system
    configure_grub

    create_user

    setup_secure_boot
    install_kernel_hooks
    configure_ram_swiper  # Verifies init_on_free=1 kernel param for cold boot mitigation
    
    # Copy installation log to /var/log (user's home is encrypted and not accessible yet)
    log "Copying installation log to /var/log..."
    cp "$LOG_FILE" "${MOUNT_POINT}/var/log/"
    chmod 777 "${MOUNT_POINT}/var/log/$(basename "$LOG_FILE")"
    log "Installation log copied to /var/log/$(basename "$LOG_FILE")"
    
    cleanup
    
    log "=========================================="
    log "Installation Complete!"
    log "=========================================="
    echo ""
    info "Security Features Enabled:"
    info "  ✓ GRUB Password Protection (prevents unauthorized bootloader access)"
    info "  ✓ Full disk encryption (LUKS)"
    info "  ✓ Encrypted /home directory (fscrypt - ext4 native encryption)"
    info "  ✓ LVM volume management"
    info "  ✓ UEFI Secure Boot ready"
    info "  ✓ Firewall (UFW) enabled"
    info "  ✓ RAM swiper - Cold boot attack mitigation"
    if [[ "$TPM_AVAILABLE" == "yes" ]]; then
    info "  ✓ TPM2 detected — GRUB tpm module records PCR measurements"
    fi
    echo ""
    info "Installation log saved to: $LOG_FILE"
    info "Log also copied to installed system: /var/log/$(basename "$LOG_FILE")"
    info "After first login, you can copy it from /var/log to your home directory"
    echo ""
    warning "IMPORTANT: Boot into UEFI firmware settings and enter Setup Mode:"
    info "  1. DISABLE Secure Boot in UEFI settings"
    info "  2. Clear/Delete all Secure Boot keys (or use 'Reset to Setup Mode')"
    info "  3. Reboot into your installed system"
    warning "You must DISABLE Secure Boot before first boot to enroll your custom keys."
    warning "After enrolling your keys, Secure Boot will be autommatically re-enabled."
    echo ""
    
    read -p "Press Enter to reboot or Ctrl+C to exit..."
    reboot
}

# Trap errors and cleanup
trap cleanup EXIT

# Run main function
main
}

_entry "$@"
