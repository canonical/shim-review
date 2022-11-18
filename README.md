This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

-------------------------------------------------------------------------------
### What organization or people are asking to have this signed?
-------------------------------------------------------------------------------
Canonical Ltd.

-------------------------------------------------------------------------------
### What product or service is this for?
-------------------------------------------------------------------------------
Ubuntu

-------------------------------------------------------------------------------
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
-------------------------------------------------------------------------------
We're a well-known Linux distro

-------------------------------------------------------------------------------
### Why are you unable to reuse shim from another distro that is already signed?
-------------------------------------------------------------------------------
We are big distro with ton of custom grub patches.

-------------------------------------------------------------------------------
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.

-------------------------------------------------------------------------------
- Name: Julian Andres Klode
- Position: engineer
- Email address: julian.klode@canonical.com
- PGP key fingerprint: AEE1 C8AA AAF0 B768 4019  C546 021B 361B 6B03 1B00

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Who is the secondary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: dann frazier
- Position: engineer
- Email address: dannf@ubuntu.com
- PGP key: dannf.pub
- PGP key fingerprint: 09F4 7DBF 2D32 EEDC 2443  EBEE 1BF8 3C5E 54FC 8640

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Were these binaries created from the 15.7 shim release tar?
Please create your shim binaries starting with the 15.7 shim release tar file: https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.7 and contains the appropriate gnu-efi source.

-------------------------------------------------------------------------------
The shim-15.7.tar.bz2 is used as the original tarball.

-------------------------------------------------------------------------------
### URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://code.launchpad.net/~ubuntu-core-dev/shim/+git/shim/+ref/master

-------------------------------------------------------------------------------
### What patches are being applied and why:
-------------------------------------------------------------------------------

Patches included also previous submission:

 * debian/patches/ubuntu-no-addend-vendor-dbx.patch: Stop addending the vendor
   dbx to the MokListX, ours is too large. Our kernels don't read it anyway,
   and new ones that will can just embed it themselves.


No new patches.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
-------------------------------------------------------------------------------
2.06 with lockdown backports, shim_lock, with rhboot/linuxefi/Canonical like implementation.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, the June 7th 2022 grub2 CVE list, or the November 15th 2022 list, have fixes for all these CVEs been applied?

* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737

* CVE-2022-2601
* CVE-2022-3775
-------------------------------------------------------------------------------
Yes.

-------------------------------------------------------------------------------
### If these fixes have been applied, have you set the global SBAT generation on your GRUB binary to 3?

-------------------------------------------------------------------------------

Yes.

### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
-------------------------------------------------------------------------------
Ubuntu shim uses a self-managed CA certificate as the VENDOR_CERT. It remains
unchanged.

This version revokes all previously used certificates, so is a clean
slate that doesn't trust any existing binary.

Pre-SBAT shim was revoked in dbx update

-------------------------------------------------------------------------------
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?

-------------------------------------------------------------------------------

All Ubuntu kernels in all currently supported series have the above
applied.

All vulnerable kernels are disallowed to boot by VENDOR_DBX by their signing
cert being revoked in vendor dbx.

-------------------------------------------------------------------------------
### Do you build your signed kernel with additional local patches? What do they do?
-------------------------------------------------------------------------------

Yes but there are like hundred patches and like 80 different kernels, so it's a bit
much to include here. There's additional secure boot enforcing patches, hardware
enablement, and zfs is built alongside.

Most interesting things are:
```
df8b92624f UBUNTU: SAUCE: (lockdown) security: lockdown: expose a hook to lock the kernel down
fede732054 UBUNTU: SAUCE: (lockdown) efi: Add an EFI_SECURE_BOOT flag to indicate secure boot mode
438296a598 UBUNTU: SAUCE: (lockdown) efi: Lock down the kernel if booted in secure boot mode
03deb74301 UBUNTU: SAUCE: (lockdown) s390: Lock down the kernel when the IPL secure flag is set
c2952ca438 UBUNTU: SAUCE: (lockdown) KEYS: Make use of platform keyring for module signature verify
9ba951d4e7 UBUNTU: SAUCE: (lockdown) arm64: Allow locking down the kernel under EFI secure boot
01f96e4abc UBUNTU: SAUCE: (lockdown) security: lockdown: Make CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT more generic
59a69f2418 UBUNTU: SAUCE: (lockdown) powerpc: lock down kernel in secure boot mode
0db545033f UBUNTU: SAUCE: integrity: Load mokx certs from the EFI MOK config table
7482fcc79c UBUNTU: SAUCE: integrity: add informational messages when revoking certs
9075b83ae9 UBUNTU: [Packaging] Revoke 2012 UEFI signing certificate as built-in
```

The above ensure that lockdown is enforced when booted with
secureboot, MOKX keys are imported into kernel .blacklist keyring, and
thus revoked kernels are prohibited from kexec/kdump.


Notable features of our config options:

```
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULE_SIG_HASH="sha512"
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_SYSTEM_REVOCATION_KEYS="debian/canonical-revoked-certs.pem"
CONFIG_SYSTEM_TRUSTED_KEYS="debian/canonical-certs.pem"
```

The above settings ensure that all drivers are signed with built-time
ephemeral signing key. In addition, we trust livepatch & 3rd-party
driver signing key for signing modules post kernel build.

Drivers signed with built-in kernel signing key:

 * `CONFIG_STAGING=y` that are listed in
   `./drivers/staging/signature-inclusion`, currently exfat, realtek
   wifi drivers only. NB! most importantly android ashmem/binder are
   _not_ signed

 * Vendored at build-time dkms modules listed in
   `debian/dkms-versions`, currently these are `zfs-linux`,
   `v4l2loopback`, `backport-iwlwifi-dkms` for ZFS, webcam and wifi
   support.

Drivers signed with `SYSTEM_TRUSTED_KEYS`:

 * Canonical Livepatch Service modules for livepatching security vulnerabilities

 * Detached reproducible builds NVIDIA proprietary driver signatures

Certificates present in `CONFIG_SYSTEM_REVOCATION_KEYS`:

 * The certificates in `CONFIG_SYSTEM_REVOCATION_KEYS` are the same as
   shim's `VENDOR_DBX` discussed below. This is to ensure that kernel
   prohibits kexec/kdump of kernels that are distrusted by the shim to
   boot. This works, even if MOKX mirroring facility fails at runtime,
   due to shim/platform deficiencies.

-------------------------------------------------------------------------------
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
-------------------------------------------------------------------------------
VENDOR_DB is not used.

-------------------------------------------------------------------------------
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
-------------------------------------------------------------------------------
We are shipping vendor_dbx that includes all previously used certificates.


-------------------------------------------------------------------------------
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
-------------------------------------------------------------------------------
Ubuntu 22.10 (kinetic kudo)
 FIXME: binutils (= 2.36.1-6ubuntu1),
 FIXME: gcc-10 (= 10.3.0-1ubuntu1),
 FIXME: libc6-dev (= 2.33-0ubuntu5),

To build:

Use included Dockerfiles;

arm64 builds are not entirely reproducible, their build id changes.


-------------------------------------------------------------------------------
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.

-------------------------------------------------------------------------------
The .log files

-------------------------------------------------------------------------------
### What changes were made since your SHIM was last signed?
-------------------------------------------------------------------------------
Rebased against 15.7

-------------------------------------------------------------------------------
### What is the SHA256 hash of your final SHIM binary?
-------------------------------------------------------------------------------
FIXME: [your text here]

-------------------------------------------------------------------------------
### How do you manage and protect the keys used in your SHIM?
-------------------------------------------------------------------------------
The CA certificate used as VENDOR_CERT is always stored offline, split
using Shamir's Secret Sharing into 7 fragments distributed globally, 3
of which are required to assemble the cert.

Thus we require international travel to be available to assemble it
and issue new certificates.

-------------------------------------------------------------------------------
### Do you use EV certificates as embedded certificates in the SHIM?
-------------------------------------------------------------------------------
No

-------------------------------------------------------------------------------
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
-------------------------------------------------------------------------------
shim, fb, mm:

    sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
    shim,3,UEFI shim,shim,1,https://github.com/rhboot/shim
    shim.ubuntu,1,Ubuntu,shim,15.4-0ubuntu2,https://www.ubuntu.com/

grub:

    sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
    grub,3,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/
    grub.ubuntu,1,Ubuntu,grub2,2.04-1ubuntu45,https://www.ubuntu.com/

fwupd:

    sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
    fwupd,1,Firmware update daemon,fwupd,1.5.11,https://github.com/fwupd/fwupd
    fwupd.ubuntu,1,Ubuntu,fwupd,1.5.11-0ubuntu2,https://launchpad.net/ubuntu/+source/fwupd

kernel.efi:

    sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
    systemd,1,The systemd Developers,systemd,245,https://www.freedesktop.org/wiki/Software/systemd
    systemd.ubuntu,1,Ubuntu,systemd,245.4-4ubuntu3.6,https://bugs.launchpad.net/ubuntu/

FIXME: Update grub fwupd sbats with real ones.

-------------------------------------------------------------------------------
### Which modules are built into your signed grub image?
-------------------------------------------------------------------------------
basic:
	all_video
	boot
	btrfs
	cat
	chain
	configfile
	echo
	efifwsetup
	efinet
	ext2
	fat
	font
	gettext
	gfxmenu
	gfxterm
	gfxterm_background
	gzio
	halt
	help
	hfsplus
	iso9660
	jpeg
	keystatus
	loadenv
	loopback
	linux
	ls
	lsefi
	lsefimmap
	lsefisystab
	lssal
	memdisk
	minicmd
	normal
	ntfs
	part_apple
	part_msdos
	part_gpt
	password_pbkdf2
	png
	probe
	reboot
	regexp
	search
	search_fs_uuid
	search_fs_file
	search_label
	sleep
	smbios
	squash4
	test
	true
	video
	xfs
	zfs
	zfscrypt
	zfsinfo
	"

amd64-only:
	cpuid
	linuxefi
	play
	tpm

installed grub:
    cryptodisk
	gcry_arcfour
	gcry_blowfish
	gcry_camellia
	gcry_cast5
	gcry_crc
	gcry_des
	gcry_dsa
	gcry_idea
	gcry_md4
	gcry_md5
	gcry_rfc2268
	gcry_rijndael
	gcry_rmd160
	gcry_rsa
	gcry_seed
	gcry_serpent
	gcry_sha1
	gcry_sha256
	gcry_sha512
	gcry_tiger
	gcry_twofish
	gcry_whirlpool
	luks
	lvm
	mdraid09
	mdraid1x
	raid5rec
	raid6rec

network grub image:
	http
	tftp

-------------------------------------------------------------------------------
### What is the origin and full version number of your bootloader (GRUB or other)?
-------------------------------------------------------------------------------
Building / Publishing
https://launchpad.net/ubuntu/+source/grub2-unsigned - same signed grub binaries for all series

Git managed source code
https://code.launchpad.net/~ubuntu-core-dev/grub/+git/ubuntu/+ref/ubuntu

Note patches debian/patches

FIXME: latest grub not public yet

-------------------------------------------------------------------------------
### If your SHIM launches any other components, please provide further details on what is launched.
-------------------------------------------------------------------------------
We load various UKIs which use systemd-boot stub to combine kernels and initrds
into a single binary.

fwupd of course.


-------------------------------------------------------------------------------
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
-------------------------------------------------------------------------------
GRUB2 may launch Windows Bootmgr on dual boot systems.
Nebooted shim+grub2 may chainloader load shim+grub2 again from disk,
which will verify things again as usual. (https://maas.io usecase).

-------------------------------------------------------------------------------
### How do the launched components prevent execution of unauthenticated code?
-------------------------------------------------------------------------------
fwupd verifies capsule signatures; kernel implements lockdown.

Our kernels also check MokListXRT for revocations for kexec.

-------------------------------------------------------------------------------
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
-------------------------------------------------------------------------------
No, our grub enforces lockdown & uses shim protocol (rhboot linuxefi
sb patches) to verify next component.

-------------------------------------------------------------------------------
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
-------------------------------------------------------------------------------
linux, various versions. They include lockdown patches & ACPI patches,
lockdown is enforced when booted with SecureBoot, config enforces
kernel module signatures under lockdown.

-------------------------------------------------------------------------------
### Add any additional information you think we may need to validate this shim.
-------------------------------------------------------------------------------

VENDOR_DBX file is included as canonical-dbx-20221103.esl
One can unpack them using `sig-list-to-certs` utility, and
finds as the changelog states:

    This vendor dbx revokes all certificates that have been used
    so far.
    - CN = Canonical Ltd. Secure Boot Signing
    - CN = Canonical Ltd. Secure Boot Signing (2017)
    - CN = Canonical Ltd. Secure Boot Signing (ESM 2018)
    - CN = Canonical Ltd. Secure Boot Signing (2019)
    - CN = Canonical Ltd. Secure Boot Signing (Ubuntu Core 2019)
    - CN = Canonical Ltd. Secure Boot Signing (2021 v1)
    - CN = Canonical Ltd. Secure Boot Signing (2021 v2)
    - CN = Canonical Ltd. Secure Boot Signing (2021 v3)


- we have disabled ExitBootServices check, to allow chainloading a
  second shim from disk, from netbooted shim+grub. All shims these
  days require signature validation thus this is safe to do. We need
  this to support secureboot in https://maas.io which by default
  netboots & recovers bare metal machines.

- we have disabled the unacceptable 5s boot delay in fallback when
  TPM is present, as it impacts bootspeed for the noninteractive
  cloud instances that have vTPM & SecureBoot.
