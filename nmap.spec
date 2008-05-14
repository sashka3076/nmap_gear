Name: nmap
Version: 4.62
Release: alt1
Epoch: 20020501

Summary: Network exploration tool and security scanner
License: GPLv2
Group: Monitoring
Url: http://nmap.org/
Packager: Dmitry V. Levin <ldv@altlinux.org>

%define srcname nmap-%version
Source: %url/dist/%srcname.tar

Patch1: nmap-4.62-alt-owl-autoheader.patch
Patch2: nmap-4.62-alt-owl-drop-priv.patch
Patch3: nmap-4.62-alt-owl-dot-dir.patch
Patch4: nmap-4.62-alt-owl-fileexistsandisreadable.patch
Patch5: nmap-4.62-alt-libdnet.patch
Patch6: nmap-4.62-svn-20080505-makefile.patch

Requires: chrooted-resolv, libdnet >= 0:1.11-alt4
BuildRequires: gcc-c++, libcap-devel, libdnet-devel
BuildRequires: libpcap-devel >= 2:0.8, libpcre-devel, libssl-devel

%description
Nmap is an utility for network exploration or security auditing.
It supports ping scanning (determine which hosts are up), many port
scanning techniques, version detection (determine service protocols and
application versions listening behind ports), and TCP/IP fingerprinting
(remote host OS or device identification).  Nmap also offers flexible
target and port specification, decoy/stealth scanning, Sun RPC scanning,
and more.

%prep
%setup -q -n %srcname
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
%patch5 -p1
%patch6 -p1
bzip2 -9 CHANGELOG

%build
aclocal
autoheader
autoconf

export ac_cv_header_libiberty_h=no
%configure \
	--with-libdnet=/usr \
	--without-liblua \
	--without-zenmap \
	--with-user=nmapuser \
	--with-chroot-empty=/var/empty \
	--with-chroot-resolv=/var/resolv \
	#
%make_build

%install
%make_install install DESTDIR=%buildroot

%pre
/usr/sbin/groupadd -r -f nmapuser
/usr/sbin/useradd -r -g nmapuser -d /dev/null -s /dev/null -n nmapuser >/dev/null 2>&1 ||:

%files
%_bindir/nmap
%_datadir/nmap
%_man1dir/nmap.*
%doc COPYING* CHANGELOG.bz2 docs/{README,*.txt}

%changelog
* Fri Apr 11 2008 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.20-alt3
- Use %%update_menus/%%clean_menus for frontend subpackage again.
- Do not package developer docs.

* Fri Oct 19 2007 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.20-alt2
- Use 1st generation OS detection system by default.

* Thu Oct 18 2007 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.20-alt1
- Updated to 4.20.

* Sat Jun 24 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.11-alt1
- Updated to 4.11.

* Wed Jun 14 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.10-alt1
- Updated to 4.10.

* Thu Jun 01 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.04-alt0.1
- Updated to 4.04BETA1.
- Patched to build with system libdnet.

* Sun Apr 23 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.03-alt1
- Updated to 4.03.

* Thu Mar 09 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.02-alt0.2
- Updated to 4.02Alpha2.
- Updated patches.

* Sun Mar 05 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.02-alt0.1
- Updated to 4.02Alpha1.
- Made droppriv patch portable.

* Fri Mar 03 2006 Dmitry V. Levin <ldv@altlinux.org> 20020501:4.01-alt1
- Updated to 4.01.
- Reviewed and reworked patches.
- Cleaned up specfile.
- Replaced menu file with desktop file.
- Updated nmapfe icons from Mandriva package.
- Updated build dependencies.

* Wed Feb 01 2006 Victor Forsyuk <force@altlinux.ru> 20020501:4.00-alt1
- 4.00
- Convert 'error' to 'fatal' in droppriv.cc (as in Owl's patch).
- Update build requirements.

* Mon Feb 07 2005 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.81-alt1
- 3.81

* Tue Jan 18 2005 ALT QA Team Robot <qa-robot@altlinux.org> 20020501:3.78-alt1.1
- Rebuilt with libstdc++.so.6.

* Wed Dec 15 2004 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.78-alt1
- Updated to 3.78.
- Localized manual pages installed by default from now.

* Sun Nov 28 2004 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.77-alt2
- Split drop-priv patch into two patches.

* Mon Nov 15 2004 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.77-alt1
- 3.77.
- Changed menu group to Networking/Other.
- Added %%post and %%postun to %name-frontend package.

* Tue Oct 19 2004 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.75-alt1
- 3.75.
- Updated autoheader.patch.
- Updated BuildRequires.

* Wed Sep 01 2004 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.70-alt1
- 3.70.
- Updated drop_priv.patch & autoheader.patch.

* Fri Jul 16 2004 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.55-alt1
- Updated to 3.55.
- Rediffed patches.
- Updated drop_priv.patch to enable MAC address printing support.

* Mon May 10 2004 ALT QA Team Robot <qa-robot@altlinux.org> 20020501:3.51-alt0.3.1
- Rebuilt with openssl-0.9.7d.

* Tue Apr 20 2004 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.51-alt0.3
- 3.51-TEST3
- Updated alt-drop_priv.patch
- Added MAC address printing

* Tue Mar 09 2004 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.51-alt0.1
- 3.51-TEST2
- added Provides

* Wed Jan 21 2004 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.50-alt1
- 3.50

* Mon Jan 12 2004 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.48-alt2
- Rebuilded with libpcap0.8
- Updated BuildRequires

* Wed Oct 08 2003 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.48-alt1
- Updated to 3.48.

* Fri Oct 03 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.47-alt1
- 3.47
- Dropped nmap-3.46-alt-pcap.patch

* Thu Oct 02 2003 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.46-alt2
- Fixed libpcap version detection again.
- Fixed build to avoid using libiberty-devel.
- Enhanced droppriv patch to make tcpip.cc/routethrough() work again.

* Sun Sep 21 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.46-alt1
- 3.46
- Removed obsoleted patch.

* Sun Sep 14 2003 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.40PVT17-alt1
- Updated to 3.40PVT17, few patches merged upstream.

* Wed Sep 10 2003 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.40PVT16-alt1
- Updated to 3.40PVT16, reviewed and reworked patches.

* Mon Jun 30 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.30-alt1
- 3.30

* Mon Jun 16 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.28-alt1
- 3.28
- Updated patches, removed obsoleted.

* Tue Jun 03 2003 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.27-alt2
- Synced with Owl's nmap-3.27-owl1 package.

* Tue Apr 29 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.27-alt1
- 3.27

* Fri Apr 25 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.26-alt1
- 3.26

* Mon Apr 21 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.25-alt1
- 3.25

* Tue Apr 08 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.21-alt1.CSW
- 3.21 "CanSecWest" release.

* Thu Mar 20 2003 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.20-alt1
- 3.20

* Fri Dec 27 2002 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.10ALPHA9-alt1
- 3.10ALPHA9

* Fri Dec 20 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 20020501:3.10ALPHA7-alt1
- 3.10ALPHA7
- Updated buildrequires

* Thu Nov 14 2002 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.10ALPHA4-alt2
- Added menuitem for nmapfe

* Wed Nov 13 2002 Aleksandr Blokhin 'Sass' <sass@altlinux.ru> 20020501:3.10ALPHA4-alt1
- 3.10ALPHA4
- Updated buildrequires.

* Mon Sep 23 2002 Dmitry V. Levin <ldv@altlinux.org> 20020501:3.10ALPHA3-alt1
- 3.10ALPHA3, redone patches.
- Fixed build warnings.
- Updated buildrequires.

* Fri Aug 02 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 3.00-alt1
- 3.00

* Fri Jul 12 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA37-alt1
- 2.54BETA37
- builded with gcc-3.1

* Thu Jun 20 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA36-alt1
- 2.54BETA36

* Mon Jun 10 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA34-alt1
- 2.54BETA34

* Wed May  1 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA33-alt1
- 2.54BETA33

* Thu Apr 18 2002 Dmitry V. Levin <ldv@alt-linux.org> 2.54BETA32-alt2
- Dropped obsolete summaries and descriptions in koi8r encoding.
- Dropped obsolete "compile" patch.
- Build with system pcap (requires libpcap >= 0.7.1-alt2).
- Added drop_priv (user=nmapuser, root=/var/resolv).

* Tue Apr  2 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA32-alt1
- 2.54BETA32

* Mon Apr  1 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA31-alt1
- 2.54BETA31

* Wed Jan  9 2002 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA30-alt3
- added Summary & description in CP1251 encoding

* Tue Dec 25 2001 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA30-alt2
- updated spec
- updated to rpm-4.0.3

* Thu Oct 16 2001 Aleksandr Blokhin (Sass) <sass@altlinux.ru> 2.54BETA30-alt1
- 2.54BETA30

* Mon Aug 13 2001 Dmitry V. Levin <ldv@altlinux.ru> 2.54BETA29-alt1
- 2.54BETA29

* Tue Jul 31 2001 Dmitry V. Levin <ldv@altlinux.ru> 2.54BETA28-alt1
- 2.54BETA28

* Thu Jul 26 2001 Dmitry V. Levin <ldv@altlinux.ru> 2.54BETA27-alt1
- 2.54BETA27

* Tue Jun 05 2001 Dmitry V. Levin <ldv@altlinux.ru> 2.54BETA25-alt1
- 2.54BETA25

* Mon Jun 04 2001 Dmitry V. Levin <ldv@altlinux.ru> 2.54BETA24-alt1
- 2.54BETA24

* Sun Mar 11 2001 Dmitry V. Levin <ldv@fandra.org> 2.54BETA22-ipl1mdk
- 2.54BETA22

* Sat Mar 10 2001 Dmitry V. Levin <ldv@fandra.org> 2.54BETA21-ipl1mdk
- 2.54BETA21

* Wed Mar 07 2001 Dmitry V. Levin <ldv@fandra.org> 2.54BETA20-ipl1mdk
- 2.54BETA20

* Thu Feb 08 2001 Dmitry V. Levin <ldv@fandra.org> 2.54BETA19-ipl1mdk
- 2.54BETA19
- Fixed group tags.

* Fri Dec 01 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA14-ipl1mdk
- 2.54BETA14

* Wed Nov 22 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA11-ipl1mdk
- 2.54BETA11

* Sat Nov 11 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA8-ipl1mdk
- 2.54BETA8

* Mon Oct 09 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA6-ipl1mdk
- 2.54BETA6

* Tue Sep 05 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA4-ipl1mdk
- 2.54BETA4

* Thu Aug 03 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA2-ipl1mdk
- 2.54BETA2

* Wed Jun 28 2000 Dmitry V. Levin <ldv@fandra.org> 2.54BETA1-ipl1mdk
- Use FHS-compatible macros.

* Wed May 31 2000 Dmitry V. Levin <ldv@fandra.org>
- 2.54BETA1

* Tue Jan  4 2000 Dmitry V. Levin <ldv@fandra.org>
- 2.3BETA12
- split into two packages

* Sun Nov 28 1999 Dmitry V. Levin <ldv@fandra.org>
- Fandra adaptions

* Sun Jan 10 1999 Fyodor <fyodor@dhp.com>
- Merged in spec file sent in by Ian Macdonald <ianmacd@xs4all.nl>

* Tue Dec 29 1998 Fyodor <fyodor@dhp.com>
- Made some changes, and merged in another .spec file sent in
  by Oren Tirosh <oren@hishome.net>

* Mon Dec 21 1998 Riku Meskanen <mesrik@cc.jyu.fi>
- initial build for RH 5.x
