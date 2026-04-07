X1-enable tpm hardware in bios

2. --modules="pgp ...

sudo sbctl verify
sudo sbctl status

grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB --modules="normal test efi_gop efi_uga search echo linux all_video gfxmenu gfxterm_background gfxterm_menu gfxterm loadenv configfile tpm" --disable-shim-lock

https://wiki.gentoo.org/wiki/Secure_Boot/GRUB#Error:_verification_requested_but_nobody_cares:_.28.3Cdrive.3E.2C.3Cpartition.3E.29.2Fgrub.2F.3Carchitecture.3E.2F.3Cgrub_module.3E.mod.
https://changmarcusyu.com/Blogs/arch-linux-secure-boot-with-grub/

https://wejn.org/2021/09/fixing-grub-verification-requested-nobody-cares/
