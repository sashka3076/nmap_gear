Name: nmap
Version: 3.10ALPHA9
Release: alt1
Serial: 20020501

Summary: Network exploration tool and security scanner
Summary(ru_RU.CP1251): Инструмент для исследования сети и сетевой безопасности.
License: GPL
Group: Monitoring
Url: http://www.insecure.org/%name
Packager: Nmap Development Team <nmap@packages.altlinux.org>

Source: %url/dist/%name-%version.tar.bz2
Source1: nmapfe.menu
Source2: nmapfe.xpm

Patch1: %name-3.10ALPHA3-alt-with_system_pcap.patch
Patch2: %name-3.10ALPHA3-alt-drop_priv.patch
Patch3: %name-3.10ALPHA3-alt-configure.patch
Patch4: %name-3.10ALPHA3-alt-build.patch

PreReq: libpcap >= 0.7.1-alt2, chrooted >= 0.2, net-tools, /var/resolv

# Automatically added by buildreq on Fri Dec 20 2002
BuildRequires: XFree86-devel XFree86-libs gcc-c++ glib-devel gtk+-devel libbfd-devel 
BuildRequires: libcap-devel libiberty-devel libpcap-devel libstdc++-devel

%package frontend
Summary: Gtk+ frontend for %name
Summary(ru_RU.CP1251): Графический интерфейс пользователя для %name
Group: Monitoring
Requires: %name = %serial:%version-%release

%description
Nmap is a utility for network exploration or security auditing. It
supports ping scanning (determine which hosts are up), many port
scanning techniques (determine what services the hosts are offering),
and TCP/IP fingerprinting (remote host operating system
identification). Nmap also offers flexible target and port
specification, decoy scanning, determination of TCP sequence
predictability characteristics, sunRPC scanning, reverse-identd
scanning, and more.

%description -l ru_RU.CP1251
Nmap - это утилита для исследования сети и аудита защиты. Она поддерживает
сканирование при помощи ping (определение действующих машин), множественное
сканирование портов (определение предоставляемых машиной сервисов) и отпечатки
TCP/IP (идентификация удалённой системы).

%description frontend
This package includes nmapfe, a Gtk+ frontend for %name. The %name package must
be installed before installing %name-frontend.

%description frontend -l ru_RU.CP1251
Этот пакет содержит nmapfe, Gtk+ интерфейс для nmap. Пакет nmap должен быть
установлен до начала установки nmap-frontend.

%prep
%setup -q
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch4 -p1

%build
aclocal
autoconf

#pushd nbase
#	aclocal -I .
#	autoconf
#popd

%configure
%make_build

%install
mkdir -p $RPM_BUILD_ROOT{%_bindir,%_man1dir,%_menudir,%_iconsdir}
mkdir -p $RPM_BUILD_ROOT%_datadir/%name
mkdir -p $RPM_BUILD_ROOT%_x11dir/{bin,man/man1}
%makeinstall nmapdatadir=$RPM_BUILD_ROOT%_datadir/%name
mv $RPM_BUILD_ROOT%_bindir/{nmapfe,xnmap} $RPM_BUILD_ROOT%_x11bindir/
mv $RPM_BUILD_ROOT%_man1dir/{nmapfe,xnmap}.1 $RPM_BUILD_ROOT%_x11mandir/man1/
install -p -m644 %SOURCE1 $RPM_BUILD_ROOT%_menudir/nmapfe
install -p -m644 %SOURCE2 $RPM_BUILD_ROOT%_iconsdir/

%pre
/usr/sbin/groupadd -r -f nmapuser >/dev/null 2>&1
/usr/sbin/useradd -r -g nmapuser -d /dev/null -s /dev/null -n nmapuser >/dev/null 2>&1 ||:

%post
/etc/chroot.d/resolv.all

%files
%_bindir/*
%_datadir/%name
%_mandir/man?/*
%doc CHANGELOG HACKING docs/{README,*.{txt,html}}

%files frontend
%_x11bindir/*
%_x11mandir/man?/*
%_menudir/*
%_iconsdir/*

%changelog
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
