This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

As of 27 June 2026, shims sent to Microsoft can only be signed by the Microsoft UEFI CA 2023. It is no longer possible to get your shim signed by the "old" Microsoft Corporation UEFI CA 2011 key. Up-to-date information from Microsoft about Secure Boot can be found here: https://support.microsoft.com/en-US/servicing/os/secure-boot/2026/02/updates-and-announcements

New signing requirements have also taken effect, and are available here: https://techcommunity.microsoft.com/blog/hardware-dev-center/updated-microsoft-uefi-signing-requirements/1062916 Please note that undergoing this shim review exempts you from yearly security audits, as long as your shim only hands off to open source boot loaders.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Organization name and website:  
Canonical Ltd. — https://www.canonical.com/

*******************************************************************************
### What's the legal data that proves the organization's genuineness?
The reviewers should be able to easily verify, that your organization is a legal entity, to prevent abuse.
Provide the information, which can prove the genuineness with certainty.
*******************************************************************************
Company/tax register entries or equivalent:  
(a link to the organization entry in your jurisdiction's register will do)  

https://find-and-update.company-information.service.gov.uk/company/06870835

The public details of both your organization and the issuer in the EV certificate used for signing .cab files at Microsoft Hardware Dev Center File Signing Services.  
(**not** the CA certificate embedded in your shim binary)

```
subject=jurisdictionC=GB, businessCategory=Private Organization, serialNumber=06870835, C=GB, L=London, O=CANONICAL GROUP LIMITED, CN=CANONICAL GROUP LIMITED
issuer=C=US, O=DigiCert, Inc., CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
notBefore=Mar 16 00:00:00 2026 GMT
notAfter=Mar 15 23:59:59 2027 GMT
```

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Ubuntu

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
We are a well-known and widely used Linux distro.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We build and sign our own bootloaders and kernels with many custom patches.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
Please upload the PGP keys to a well-known keyserver like keyserver.ubuntu.com and/or include them in the review as an .asc file, and point to them here.

*******************************************************************************
- Name: Julian Andres Klode
- Position: engineer
- Email address: julian.klode@canonical.com
- PGP key fingerprint: AEE1 C8AA AAF0 B768 4019  C546 021B 361B 6B03 1B00
- File/keyserver location: https://keyserver.ubuntu.com/pks/lookup?search=0x021B361B6B031B00&op=index

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Mate Kukri
- Position: Software Engineer
- Email address: mate.kukri@canonical.com
- PGP key fingerprint: 844F 395E 47DA B2E2 900A  FEA7 7063 490E 7DB7 7482
- File/keyserver location: https://keyserver.ubuntu.com/pks/lookup?op=vindex&search=0x844F395E47DAB2E2900AFEA77063490E7DB77482

Note on contacts and keys since our 15.8 review:

 * Julian Andres Klode's key (AEE1 C8AA AAF0 B768 4019  C546 021B 361B 6B03 1B00)
   is unchanged and has already been verified in the 15.8 review.
 * Mate Kukri has rotated his key: the RSA4096 key above
   (844F 395E 47DA B2E2 900A  FEA7 7063 490E 7DB7 7482) replaces his previous
   RSA2048 key (9850 FD0C 92D5 2276 794E  4595 5243 F6D8 1246 00EC), and is
   cross-signed by that old key. As his key has changed, it may require
   re-verification.
 * dann frazier, who was a secondary contact in previous submissions, has been
   removed as he is no longer at Canonical.

*******************************************************************************
### Were these binaries created from the 16.1 shim release tar?
Please create your shim binaries starting with the 16.1 shim release tar file: https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/16.1 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum
(SHA256, SHA512) with the following ones:

```
46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603  shim-16.1.tar.bz2
ca5f80e82f3b80b622028f03ef23105c98ee1b6a25f52a59c823080a3202dd4b9962266489296e99f955eb92e36ce13e0b1d57f688350006bba45f2718f159fb  shim-16.1.tar.bz2
```

Make sure that you've verified that your build process uses that file
as a source of truth (excluding external patches) and its checksum
matches. You can also further validate the release by checking the PGP
signature: there's [a detached
signature](https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2.asc)

The release is signed by the maintainer Peter Jones - his master key
has the fingerprint `B00B48BC731AA8840FED9FB0EED266B70F4FEF10` and the
signing sub-key in the signature here has the fingerprint
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372`. A copy of his public key
is included here for reference:
[pjones.asc](https://github.com/rhboot/shim-review/blob/main/pjones.asc)

Once you're sure that the tarball you are using is correct and
authentic, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes. The shim-16.1.tar.bz2 release tarball is used as the orig tarball. Its
SHA256 and SHA512 checksums match the ones above, and the detached PGP signature
verifies against Peter Jones' key.

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://code.launchpad.net/~ubuntu-core-dev/shim/+git/shim/+ref/master

The exact package built is shim 16.1-0ubuntu1, published for Ubuntu 26.04 LTS
(Resolute) in https://launchpad.net/~ubuntu-uefi-team/+archive/ubuntu/build

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
Patches (debian/patches), applied on top of the shim 16.1 release tarball:

 * ubuntu-no-addend-vendor-dbx.patch: Stop addending the vendor dbx to the
   MokListX, ours is too large. Our kernels don't read it anyway, and new ones
   that will can just embed it themselves. (Carried over from previous
   submissions.)
 * Fix-build-with-binutils-2.46.patch: Build fix for the binutils 2.46 toolchain
   used in Ubuntu 26.04.
 * test-fix-strrchr-usage.patch: Test-only fix for strrchr usage; does not affect
   the produced binaries.

Build process modifications (debian/rules), passed to the shim build:

 * VENDOR_CERT_FILE=debian/canonical-uefi-ca.der
 * VENDOR_DBX_FILE=debian/canonical-dbx-20221103.esl
 * RELEASE=16, COMMIT_ID=afc49558b34548644c1cd0ad1b6526a9470182ed
 * FALLBACK_NONINTERACTIVE=1 (no interactive 5s fallback delay)
 * DISABLE_EBS_PROTECTION=1 (see the additional information below)
 * DISABLE_REMOVABLE_LOAD_OPTIONS=1
 * POST_PROCESS_PE_FLAGS=-n to set the NX_COMPAT flag on all Ubuntu shims.
 * SBAT_AUTOMATIC_DATE=2025051000 to apply the latest SBAT revocations shipped in
   shim 16.1 (resulting in the SBAT policy "shim,4\ngrub,5\ngrub.proxmox,2").

The previous "Build-an-additional-NX-shim" patch has been dropped: we now build a
single NX_COMPAT shim per architecture, as our NX rollout is complete.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
Yes, the NX_COMPAT bit is set on all Ubuntu shims (POST_PROCESS_PE_FLAGS=-n).

During our NX rollout we shipped two shims per architecture (one with and one
without NX_COMPAT). That rollout is now complete, so as of shim 16.1-0ubuntu1 we
ship a single NX_COMPAT shim per architecture.

Our entire boot stack is NX-compatible:

 * shim 16 auto-detects the platform's NX requirements and only requires NX from
   chainloaded binaries when the underlying platform demands it (see
   `set_shim_nx_policy()`).
 * We have shipped an NX-compatible GRUB2 since Ubuntu 24.10.
 * Our kernels have been NX-compatible for a long time.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
- GRUB 2.06 with "Downstream RHEL/Fedora/Debian/Canonical-like implementation"
  (older stable series)
- GRUB 2.12 and later (2.14 in Ubuntu 26.04) with "Upstream GRUB2 shim_lock
  verifier" with the peimage loader added

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
* February 2025
  * Details: https://lists.gnu.org/archive/html/grub-devel/2025-02/msg00024.html, SBAT increase to 5
  * CVE-2024-45774
  * CVE-2024-45775
  * CVE-2024-45776
  * CVE-2024-45777
  * CVE-2024-45778
  * CVE-2024-45779
  * CVE-2024-45780
  * CVE-2024-45781
  * CVE-2024-45782
  * CVE-2024-45783
  * CVE-2025-0622
  * CVE-2025-0624
  * CVE-2025-0677
  * CVE-2025-0678
  * CVE-2025-0684
  * CVE-2025-0685
  * CVE-2025-0686
  * CVE-2025-0689
  * CVE-2025-0690
  * CVE-2025-1118
  * CVE-2025-1125
*******************************************************************************
Yes.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 5?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,5,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
Yes. Our GRUB2 binary in Ubuntu 26.04 has upstream SBAT generation 5:

    grub,5,Free Software Foundation,grub,2.14,https://www.gnu.org/software/grub/

Correspondingly, this shim ships an SBAT policy of "shim,4\ngrub,5\ngrub.proxmox,2"
(via SBAT_AUTOMATIC_DATE=2025051000), so it refuses to boot GRUB2 binaries older
than SBAT generation 5.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************

 * Pre-SBAT shims were revoked in a dbx update.
 * We use a self-managed CA certificate as the VENDOR_CERT.
 * Vulnerable artefacts signed by the CA are revoked via VENDOR_DBX or SBAT.
 * This shim ships an SBAT policy of "shim,4\ngrub,5\ngrub.proxmox,2", so it will
   not boot GRUB2 builds older than SBAT generation 5, i.e. those affected by the
   CVEs listed above.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
All Ubuntu kernels in all currently supported series have the above
applied.

All vulnerable kernels are disallowed to boot by VENDOR_DBX by their signing
cert being revoked in vendor dbx.

*******************************************************************************
### How does your signed kernel enforce lockdown when your system runs with Secure Boot enabled?
Hint: If it does not, we are not likely to sign your shim.
*******************************************************************************
When the system is booted with UEFI Secure Boot enabled, shim reflects this via
the EFI secure boot state; our kernels detect it and automatically enter
integrity lockdown mode (CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT together with our
SAUCE lockdown patches listed below).

Under lockdown, interfaces that could be used to modify the running kernel or
extract key material are restricted (e.g. /dev/mem and /dev/kmem, unsigned module
loading, kexec of unsigned images, kgdb, certain ACPI table overrides,
efivar_ssdt_load, etc.), and kernel module signature verification is enforced.
This ties the Secure Boot chain of trust into the running kernel and prevents
loading unauthenticated code into ring 0.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
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

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
VENDOR_DB is not used.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************
We are re-using our CA certificate. We ship a VENDOR_DBX
(canonical-dbx-20221103.esl) that includes/revokes all Canonical signing
certificates used so far, and we additionally rely on SBAT-based revocation
(shim,4 / grub,5) so that older, vulnerable GRUB2 binaries can no longer be
chainloaded by this shim.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
The shim binaries were built in Ubuntu 26.04 LTS (Resolute).

The provided Dockerfile should reproduce the binaries, this is also demonstrated
by a GitHub workflow.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
The `buildlog_*` files.

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************

 * New upstream shim 16.1 (previously 15.8).
 * We now ship a single NX_COMPAT shim per architecture; the separate non-NX shim
   has been dropped, as our NX rollout is complete.
 * We apply the latest SBAT revocations shipped in shim 16.1
   (SBAT_AUTOMATIC_DATE=2025051000, giving the policy "shim,4\ngrub,5\ngrub.proxmox,2"),
   revoking pre-generation-5 GRUB2.
 * GRUB2 has been updated to 2.14 (upstream SBAT generation 5) in Ubuntu 26.04.
 * From 27 June 2026, shim is signed by the Microsoft UEFI CA 2023.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************

    $ sha256sum shim*.efi
    3a6d2d3378a15372336bf00ef1e0e414563d25956f2c24bdb94afa91bee2f28e  shimaa64.efi
    413815fe5a103fb2eb17e31a672904984b997b7718e98396a4292bd59b8f257f  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
The CA certificate used as VENDOR_CERT is always stored offline, split
using Shamir's Secret Sharing into 7 fragments distributed globally, 3
of which are required to assemble the cert.

Thus we require international travel to be available to assemble it
and issue new certificates.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
No

*******************************************************************************
### Are you embedding a CA certificate in your shim?
A _yes_ or _no_ will do. There's no penalty for the latter. However,
if _yes_: does that certificate include the X509v3 Basic Constraints
to say that it is a CA? See the [docs](./docs/) for more guidance
about this.
*******************************************************************************
Yes. Our VENDOR_CERT (canonical-uefi-ca.der) is a CA certificate, and it includes
the X509v3 Basic Constraints extension marking it as a CA:

    X509v3 Basic Constraints: critical
        CA:TRUE

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --dump-section .sbat=/dev/stdout YOUR_EFI_BINARY` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************

shim, fb, mm:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.ubuntu,1,Ubuntu,shim,16.1-0ubuntu1,https://www.ubuntu.com/
```

grub (Ubuntu 26.04; versions vary per series):

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,5,Free Software Foundation,grub,2.14,https://www.gnu.org/software/grub/
grub.ubuntu,2,Ubuntu,grub2,2.14-2ubuntu1,https://www.ubuntu.com/
grub.ubuntu26,1,Ubuntu,grub2,2.14-2ubuntu1,https://www.ubuntu.com/
grub.peimage,2,Canonical,grub2,2.14-2ubuntu1,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
```

fwupd (versions vary per series):

```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd,1,Firmware update daemon,fwupd,$UPSTREAM_VERSION$,https://github.com/fwupd/fwupd
fwupd.ubuntu,1,Ubuntu,fwupd,$PACKAGE_VERSION$,https://launchpad.net/ubuntu/+source/fwupd
```

kernel.efi / UKI (versions vary per series):

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
systemd,1,The systemd Developers,systemd,$UPSTREAM_VERSION$,https://www.freedesktop.org/wiki/Software/systemd
systemd.ubuntu,1,Ubuntu,systemd,$PACKAGE_VERSION$,https://bugs.launchpad.net/ubuntu/
```

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************

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

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
We only use systemd-stub, not systemd-boot.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
Building / Publishing
https://launchpad.net/ubuntu/+source/grub2-unsigned - same signed grub binaries for all series

In Ubuntu 26.04 LTS (Resolute) this is grub2-unsigned 2.14-2ubuntu1.

Git managed source code
https://code.launchpad.net/~ubuntu-core-dev/grub/+git/ubuntu/+ref/ubuntu

Note patches debian/patches

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
We load various UKIs which use systemd-boot stub to combine kernels and initrds
into a single binary.

We use fwupd as a firmware updater.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************
GRUB2 may launch Windows Bootmgr on dual boot systems.
Nebooted shim+grub2 may chainloader load shim+grub2 again from disk,
which will verify things again as usual. (https://maas.io usecase).

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
fwupd verifies capsule signatures; kernel implements lockdown.

Our kernels also check MokListXRT for revocations for kexec.

*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
No, our GRUB enforces lockdown & uses shim protocol to verify next component.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
linux, various versions. They include lockdown patches & ACPI patches,
lockdown is enforced when booted with SecureBoot, config enforces
kernel module signatures under lockdown.

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours. 

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************

 * Julian Andres Klode has done shim reviews in the past.
 * Mate Kukri has done shim reviews, including during the 15.8 and 16.1 rollouts.

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************

 * VENDOR_DBX file is included as `canonical-dbx-20221103.esl`.
   One can unpack them using `sig-list-to-certs` utility.

 * We have disabled the ExitBootServices check:
   - In the case of GRUB 2.06, in order to allow chainloading EFI executables. GRUB 2.06 uses the
     older linuxefi loader for verifying kernels, and it verifies chainloaded EFI executables via the
     firmware only.
   - In order to allow booting artefacts directly from shim that do not have the need to do further verifications.
     For instance, we build CVM cloud images that directly boot UKIs from shim that do not need
     to do further verifications.

 * We have disabled the removable media fallback load options
   (DISABLE_REMOVABLE_LOAD_OPTIONS=1).

 * We have disabled the unacceptable 5s boot delay in fallback when
   TPM is present, as it impacts bootspeed for the noninteractive
   cloud instances that have vTPM & SecureBoot.

 * We currently use shim itself to roll out SbatLevel. `revocations.efi` isn't used currently.
   This might change in the future.

 * In addition to the amd64 and arm64 shims submitted here, the PPA also builds an
   amd64v3 (x86-64-v3) variant of the shim package for the archive. That variant
   is not part of this signing submission; only the standard amd64 (shimx64.efi)
   and arm64 (shimaa64.efi) binaries are submitted for signing.
