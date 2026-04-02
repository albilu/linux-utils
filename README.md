# linux-utils

Bash scripts for installing and recovering Debian-based systems with Full Disk
Encryption (LUKS/LVM) and UEFI Secure Boot using custom keys.

## Scripts

| Script                    | Purpose                                                |
| ------------------------- | ------------------------------------------------------ |
| `debian-fde-installer.sh` | Automated FDE installer for Debian, Kali, PureOS       |
| `chroot.sh`               | Mount and chroot into an installed system for recovery |

### Usage
1. Boot from a Debian Live USB as root.
2. Run the installer script:
   ```bash
   curl -sSL https://raw.githubusercontent.com/albilu/linux-utils/refs/heads/master/debian-fde-installer.sh | bash
   ```
   or
   ```bash
   curl -sSL https://raw.githubusercontent.com/albilu/linux-utils/refs/heads/master/chroot.sh | bash
   ```

## debian-fde-installer.sh

Installs a Debian-based system with:

- LUKS1/LUKS2 full-disk encryption (GRUB version auto-detected)
- LVM (swap + root logical volumes)
- UEFI Secure Boot with generated PK/KEK/db keys
- Keyfile in initramfs for single-passphrase boot
- GRUB password protection and auto-signing hooks on kernel updates
- fscrypt-ready ext4 root, NetworkManager, PipeWire/PulseAudio, UFW

### Security layer coverage

| # | Layer | Mechanism | Protects against |
|---|---|---|---|
| 1 | **Firmware** | BIOS/UEFI password | Unauthorized changes to boot order, disabling Secure Boot, or booting from external media |
| 2 | **Secure Boot** | Custom PK/KEK/db keys; all EFI executables signature-verified | Unsigned or tampered bootloader running before the OS |
| 3 | **ESP** (`/dev/sda1`) | `grub.cfg` embedded inside signed EFI binary (`grub-mkstandalone`); no separate config file on the unencrypted partition | Editing boot parameters without breaking the Secure Boot signature |
| 4 | **Bootloader** | GRUB password (PBKDF2 via `grub-mkpasswd-pbkdf2`) | Interactive attacks: editing menu entries, accessing GRUB shell |
| 5 | **Full disk encryption** | LUKS (`/dev/sda2`); kernel + initramfs live inside the encrypted volume | Data at rest; kernel/initramfs tampering without the passphrase |
| 6 | **Volume management** | LVM root + swap both inside LUKS | Swap leaking plaintext memory pages to disk |
| 7 | **Home directory** | fscrypt (ext4 native encryption), PAM-integrated auto-unlock | Per-user data exposure even if root volume is accessed |
| 8 | **Cold boot / memory** | Kernel parameter `init_on_free=1` (zeroes freed pages and slab objects) | Key material lingering in RAM after process exit or reboot |

**NOTE:** IT IS VERY IMPORTANT TO SET A BIOS/FIRWARE PASSWORD, AS THE PRIMARY ATTACK SURFACE TO THIS CONFIGURATION IS PHYSICAL ACCESS TO THE MACHINE TO DISABLE SECURE BOOT OR RESET THE FIRMWARE TO ALLOW MALICIOUS BOOTLOADERS.

**Requirements:** UEFI system, booted from a Debian Live USB as root.

```bash
sudo ./debian-fde-installer.sh
```

The script prompts for: target disk, hostname, username, swap size, timezone,
locale, keyboard layout, distribution, LUKS version, and passphrases.
All destructive steps require explicit confirmation (`YES`).

### Post-install: enroll Secure Boot keys

After first boot, log in as root and enroll the generated keys:

```bash
chattr -i /sys/firmware/efi/efivars/{PK,KEK,db,dbx}-*
efi-updatevar -f /etc/sb_keys/db.auth db
efi-updatevar -f /etc/sb_keys/KEK.auth KEK
efi-updatevar -f /etc/sb_keys/PK.auth PK
chattr +i /sys/firmware/efi/efivars/{PK,KEK,db,dbx}-*
```

Then enter UEFI firmware settings and enable Secure Boot.

## chroot.sh

Mounts an existing Linux installation (including LUKS-encrypted and LVM setups)
and drops into a chroot shell for recovery or maintenance.

```bash
sudo ./chroot.sh
```

Handles LUKS decryption, LVM activation, and bind-mounting `/dev`, `/proc`,
`/sys`, `/run`. Offers to unmount and close LUKS on exit.

## Troubleshooting

**GRUB doesn't ask for passphrase** — verify cryptodisk is loaded:

```bash
grep cryptodisk /boot/grub/grub.cfg   # must show: insmod cryptodisk
update-grub && /etc/kernel/postinst.d/zz-sign-grub
```

**Secure Boot verification failed** — temporarily disable SB, then:

```bash
mokutil --sb-state
efi-readvar
```

Re-enroll keys if needed.

**Cannot write EFI variables** — variables may be immutable:

```bash
chattr -i /sys/firmware/efi/efivars/{PK,KEK,db,dbx}-*
```

## Security notes

- Back up `/etc/sb_keys/` to offline storage immediately after install
- The LUKS passphrase is the last line of defence — use 20+ characters
- Secure Boot prevents bootloader tampering; it does not protect against
  physical access to unlocked storage
