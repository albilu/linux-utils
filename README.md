# linux-utils

Bash scripts for installing and recovering Debian-based systems with Full Disk
Encryption (LUKS/LVM) and UEFI Secure Boot using custom keys.

## Scripts

| Script                    | Purpose                                                |
| ------------------------- | ------------------------------------------------------ |
| `debian-fde-installer.sh` | Automated FDE installer for Debian, Kali, PureOS       |
| `chroot.sh`               | Mount and chroot into an installed system for recovery |

## debian-fde-installer.sh

Installs a Debian-based system with:

- LUKS1/LUKS2 full-disk encryption (GRUB version auto-detected)
- LVM (swap + root logical volumes)
- UEFI Secure Boot with generated PK/KEK/db keys
- Keyfile in initramfs for single-passphrase boot
- GRUB password protection and auto-signing hooks on kernel updates
- fscrypt-ready ext4 root, NetworkManager, PipeWire/PulseAudio, UFW

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
