Name: nmap
Version: 2.54BETA32
Release: alt1
Serial: 20020110

Summary: Network exploration tool and security scanner
Summary(ru_RU.CP1251): Инструмент для исследования сети и сетевой безопасности.
Summary(ru_RU.KOI8-R): йОУФТХНЕОФ ДМС ЙУУМЕДПЧБОЙС УЕФЙ Й УЕФЕЧПК ВЕЪПРБУОПУФЙ.
License: GPL
Group: Monitoring
Url: http://www.insecure.org/%name

Source: %name-%version.tar.bz2
Patch: %name-2.54BETA20-compile.patch

# Automatically added by buildreq on Mon Apr 01 2002
BuildRequires: XFree86-devel XFree86-libs glib-devel gtk+-devel libpcap-devel

%package frontend
Summary: Gtk+ frontend for %name
Summary(ru_RU.CP1251): Графический интерфейс пользователя для %name
Group: Monitoring
Requires: %name = %version-%release

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
Nmap это утилита для исследования сети и аудита защиты. Она поддерживает
сканирование при помощи ping (определение действующих машин), множественное
сканирование портов (определение предоставляемых машиной сервисов) и отпечатки
TCP/IP (идентификация удалённой системы).

%description -l ru_RU.KOI8-R
Nmap ЬФП ХФЙМЙФБ ДМС ЙУУМЕДПЧБОЙС УЕФЙ Й БХДЙФБ ЪБЭЙФЩ. пОБ РПДДЕТЦЙЧБЕФ
УЛБОЙТПЧБОЙЕ РТЙ РПНПЭЙ ping (ПРТЕДЕМЕОЙЕ ДЕКУФЧХАЭЙИ НБЫЙО), НОПЦЕУФЧЕООПЕ
УЛБОЙТПЧБОЙЕ РПТФПЧ (ПРТЕДЕМЕОЙЕ РТЕДПУФБЧМСЕНЩИ НБЫЙОПК УЕТЧЙУПЧ) Й ПФРЕЮБФЛЙ
TCP/IP (ЙДЕОФЙЖЙЛБГЙС ХДБМЈООПК УЙУФЕНЩ).

%description frontend
This package includes nmapfe, a Gtk+ frontend for %name. The %name package must
be installed before installing %name-frontend.

%description frontend -l ru_RU.CP1251
Этот пакет содержит nmapfe, Gtk+ интерфейс для nmap. Пакет nmap должен быть
установлен до начала установки nmap-frontend.

%description frontend -l ru_RU.KOI8-R
ьФПФ РБЛЕФ УПДЕТЦЙФ nmapfe, Gtk+ ЙОФЕТЖЕКУ ДМС %name. рБЛЕФ %name ДПМЦЕО ВЩФШ
ХУФБОПЧМЕО ДП ОБЮБМБ ХУФБОПЧЛЙ %name-frontend.

%prep
%setup -q
%patch -p1

%build
%configure
%make_build

%install
mkdir -p $RPM_BUILD_ROOT{%_bindir,%_mandir/man1}
mkdir -p $RPM_BUILD_ROOT%_datadir/{%name,gnome/apps/Utilities}
mkdir -p $RPM_BUILD_ROOT%_x11dir/{bin,man/man1}
%makeinstall nmapdatadir=$RPM_BUILD_ROOT%_datadir/%name
mv $RPM_BUILD_ROOT%_bindir/{nmapfe,xnmap} $RPM_BUILD_ROOT%_x11bindir
mv $RPM_BUILD_ROOT%_mandir/man1/{nmapfe,xnmap}.1 $RPM_BUILD_ROOT%_x11mandir/man1

%files
%_bindir/*
%_datadir/%name
%_mandir/man?/*
%doc CHANGELOG docs/{README,*.{txt,html}}

%files frontend
%_x11bindir/*
%_x11mandir/man?/*

%changelog
* Mon Apr 02 2002 Sass <sass@altlinux.ru> 2.54BETA32-alt1
- 2.54BETA32

* Mon Apr 01 2002 Sass <sass@altlinux.ru> 2.54BETA31-alt1
- 2.54BETA31

* Wed Jan 09 2002 Sass <sass@altlinux.ru> 2.54BETA30-alt3
- added Summary & description in CP1251 encoding

* Tue Dec 25 2001 Sass <sass@altlinux.ru> 2.54BETA30-alt2
- updated spec
- updated to rpm-4.0.3

* Thu Oct 16 2001 Sass <sass@altlinux.ru> 2.54BETA30-alt1
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
