Name: nmap
Version: 3.55
Release: alt1
Serial: 20020501

Summary: Network exploration tool and security scanner
License: GPL
Group: Monitoring
Url: http://www.insecure.org/%name
Packager: Nmap Development Team <nmap@packages.altlinux.org>
Summary(ru_RU.CP1251): Инструмент для исследования сети и сетевой безопасности.

Source: %url/dist/%name-%version.tar.bz2
Source1: nmapfe.menu
Source2: nmapfe.xpm

Patch1: nmap-3.55-alt-glibc.patch
Patch2: nmap-3.55-alt-autoheader.patch
Patch3: nmap-3.55-alt-owl-libpcap.patch
Patch4: nmap-3.55-alt-drop_priv.patch

PreReq: libpcap >= 2:0.7.2-alt2, chrooted-resolv

# Automatically added by buildreq on Sat Jan 10 2004
BuildRequires: XFree86-devel gcc-c++ glib-devel gtk+-devel libcap-devel libpcap-devel libpcre-devel libssl-devel libstdc++-devel

%package frontend
Summary: Gtk+ frontend for %name
Summary(ru_RU.CP1251): Графический интерфейс пользователя для %name
Group: Monitoring
Requires: %name = %serial:%version-%release
Provides: nmapfe

%description
Nmap is designed to allow system administrators and curious individuals
to scan large networks to determine which hosts are up and what services
they are offering.  Nmap supports a large number of scanning techniques,
such as: UDP, TCP connect(), TCP SYN (half open), ftp proxy (bounce
attack), Reverse-ident, ICMP (ping sweep), FIN, ACK sweep, Xmas Tree,
SYN sweep, IP Protocol, and Null scan.  Nmap also offers a number of
advanced features such as remote OS detection via TCP/IP fingerprinting,
stealth scanning, dynamic delay and retransmission calculations, parallel
scanning, detection of down hosts via parallel pings, decoy scanning, port
filtering detection, direct (non-portmapper) RPC scanning, fragmentation
scanning, and flexible target and port specification.

%description -l ru_RU.CP1251
Nmap - это утилита для исследования сети и аудита защиты. Она поддерживает
сканирование при помощи ping (определение действующих машин), множественное
сканирование портов (определение предоставляемых машиной сервисов) и отпечатки
TCP/IP (идентификация удалённой системы).

%description frontend
This package includes nmapfe, a Gtk+ frontend for %name.

%description frontend -l ru_RU.CP1251
Этот пакет содержит nmapfe, Gtk+ интерфейс для nmap.

%prep
%setup -q -n %name-%version
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1
find -type f -name \*.orig -print -delete

%build
aclocal
autoheader
autoconf

export ac_cv_header_libiberty_h=no
%configure --with-libpcre=yes
%make_build
bzip2 -9fk CHANGELOG

%install
%__mkdir_p $RPM_BUILD_ROOT{%_bindir,%_man1dir,%_iconsdir}
%__mkdir_p $RPM_BUILD_ROOT%_datadir/%name
%__mkdir_p $RPM_BUILD_ROOT%_x11dir/{bin,man/man1}
%makeinstall nmapdatadir=$RPM_BUILD_ROOT%_datadir/%name
%__mv $RPM_BUILD_ROOT%_bindir/{nmapfe,xnmap} $RPM_BUILD_ROOT%_x11bindir/
%__mv $RPM_BUILD_ROOT%_man1dir/{nmapfe,xnmap}.1 $RPM_BUILD_ROOT%_x11mandir/man1/
%__install -pD -m644 %SOURCE1 $RPM_BUILD_ROOT%_menudir/nmapfe
%__install -p -m644 %SOURCE2 $RPM_BUILD_ROOT%_iconsdir/

%pre
/usr/sbin/groupadd -r -f nmapuser
/usr/sbin/useradd -r -g nmapuser -d /dev/null -s /dev/null -n nmapuser >/dev/null 2>&1 ||:

%post
/etc/chroot.d/resolv.all

%files
%_bindir/*
%_datadir/%name
%_mandir/man?/*
%doc CHANGELOG.bz2 HACKING docs/{README,*.{txt,html}}

%files frontend
%_x11bindir/*
%_x11mandir/man?/*
%_menudir/*
%_iconsdir/*

%changelog
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
