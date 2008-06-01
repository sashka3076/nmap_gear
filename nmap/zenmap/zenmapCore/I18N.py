#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2005 Insecure.Com LLC.
#
# Author: Adriano Monteiro Marques <py.adriano@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import locale

from zenmapCore.Name import APP_NAME, APP_DISPLAY_NAME, APP_WEB_SITE, NMAP_DISPLAY_NAME

LC_ALL = locale.setlocale(locale.LC_ALL, '')
LANG, ENC = locale.getdefaultlocale()
ERRORS = "ignore"

# If not correct locale could be retrieved, set en_US.utf8 as default
if ENC == None:
    ENC = "utf8"

if LANG == None:
    LANG = "en_US"

try:
    import gettext
    from gettext import gettext as _

    gettext.install(APP_NAME, unicode=True)

except ImportError:
    # define _() so program will not fail
    import __builtin__
    __builtin__.__dict__["_"] = str

if __name__ == '__main__':
    print _('%s - The %s frontend' % (APP_DISPLAY_NAME, NMAP_DISPLAY_NAME))
