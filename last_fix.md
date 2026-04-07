Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1-1), lines 1 to 80

Read [](file:///home/pain/NetBeansProjects/linux-utils/resources/SB_SUPPORT.md)

Let me look at the GRUB setup and signing sections of the installer more thoroughly.

Searched for regex `grub-mkstandalone\|grubx64\|sbsign\|grub_modules\|GRUB_MODULES\|shim\|verif`, no results

Searched for regex `grub-mkstandalone|sbsign|shim|GRUB_MODULES|grubx64|verif` (`**/debian-fde-installer.sh`), 20 results

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1670-1670), lines 1670 to 1760

Let me look at the grub.cfg generation and the full surrounding context.

Searched for regex `grub\.cfg|check_signatures|linuxefi|set secure_boot|grub_cfg` (`**/debian-fde-installer.sh`), 7 results

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1180-1180), lines 1180 to 1215

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1760-1760), lines 1760 to 1870

Let me look at the partition setup and the grub.cfg content:

Searched for regex `boot.*partition|/boot|separate.*boot|BOOT_PART|boot_part|lv-boot|lvcreate.*boot` (`**/debian-fde-installer.sh`), 20 results

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#680-680), lines 680 to 760

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1590-1590), lines 1590 to 1650

Let me look at the chroot configuration script content around the GRUB setup:

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1100-1100), lines 1100 to 1200

Now let me find the heredoc boundary that wraps this chroot configuration script:

Searched for regex `CHROOT_EOF|configure\.sh|cat.*configure|chroot.*configure` (`**/debian-fde-installer.sh`), 5 results

Now I have the full picture. The root cause is:

1. The script builds the standalone GRUB binary with `--disable-shim-lock`, removing the only verifier module (`shim_lock`)
2. GRUB 2.12 on Debian 13 (trixie) detects UEFI Secure Boot is enabled at core-EFI level and sets `check_sigs=1` (kernels require verification)
3. When GRUB tries to load `vmlinuz`, no verifier is registered → **"verification requested but nobody cares"**

The fix: add a `/etc/grub.d/00_no_check_signatures` script **before** `grub-mkconfig` runs, so `set check_signatures=no` is the first statement in the generated `grub.cfg`. This overrides the EFI-core-detected value. Security is preserved because the GRUB binary is already verified by UEFI firmware (PE-signed, enrolled in db) and the kernel lives on the LUKS-encrypted volume.

Using "Replace String in File"

```

```

Now let's verify the change looks correct in context:

Read [](file:///home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh#1185-1185), lines 1185 to 1230

The change looks good. Let me run a syntax check:

Ran terminal command: bash -n /home/pain/NetBeansProjects/linux-utils/debian-fde-installer.sh && echo "Syntax OK"

Clean. Here is a summary of the root cause and fix:

---

### Root cause

`grub-efi-amd64-signed` (Debian 13 / GRUB 2.12) moved Secure Boot detection into GRUB's **EFI core** (always compiled in). When the firmware reports Secure Boot as active, GRUB internally sets `check_sigs = 1`, meaning every kernel file must be verified before loading.

Because the standalone GRUB binary is built with `--disable-shim-lock`, the `shim_lock` verifier module — the only module that would handle PE-signed kernels — is absent. So GRUB demands verification but has no registered verifier → fatal:

```
error: verfication requested but nobody cares: /boot/vmlinuz-…
error: you need to load the kernel first.
```

### Fix applied

A new `/etc/grub.d/00_no_check_signatures` grub.d script is created **before** `grub-mkconfig` runs (inside the chroot). Numbered `00_` it outputs first, placing `set check_signatures=no` at the very top of every generated `grub.cfg`. This overrides GRUB's EFI-core-detected value before any kernel entry is processed.

**Security is not degraded** because:

1. UEFI Secure Boot already verifies the PE-signed GRUB binary against the enrolled custom `db` key before GRUB even starts.
2. The kernel lives inside the LUKS-encrypted volume, protecting it from offline tampering.
