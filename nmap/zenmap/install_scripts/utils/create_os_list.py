#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2005 Insecure.Com LLC.
#
# Author: Adriano Monteiro Marques <py.adriano@gmail.com>
#         David Fifield <david@bamsoftware.com>
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

# This program reads the Nmap OS fingerprint database file and writes its
# contents in preprocessed pickled form to the file os_db.dmp, which
# contains a dict mapping OS classes to lists of OS names.

import cPickle
import os.path
import re
import sys

NMAP_OS_DB = os.path.join("..", "nmap-os-db")

OS_DB_DUMP = os.path.join("share", "zenmap", "misc", "os_db.dmp")

r_fingerprint = re.compile("^Fingerprint\s+(.*)")
r_class = re.compile("^Class\s+(.*)")

def parse(os_file):
    """Return a dict that maps OS classes to lists of OS names that use that
    class."""
    os_dict = {}
    for fp in os_file.read().split("\n\n"):
        os_name = None
        for line in fp.split("\n"):
            m = r_fingerprint.match(line)
            if m:
                os_name = m.groups()[0]
                continue
            m = r_class.match(line)
            if m and os_name:
                os_class = m.groups()[0]
                l = os_dict.setdefault(os_class, [])
                if os_name not in l:
                    l.append(os_name)
    return os_dict

def write_os_db_dump(osd, file_name):
    f = open(file_name, "w")
    try:
        cPickle.dump(osd, f)
    finally:
        f.close()

def load_dumped_os():
    f = open(os_dump)
    osd = cPickle.load(f)
    f.close()

    return osd

if __name__ == "__main__":
    osd = {}
    for file_name in (NMAP_OS_DB,):
        try:
            f = open(file_name, "r")
        except IOError:
            print >> sys.stderr, """\
Can't open %s for reading.
This script (%s) must be run from the root of a
Zenmap distribution that has an Nmap distribution as its parent directory.""" % (file_name, sys.argv[0])
            sys.exit(1)
        osd.update(parse(f))
        f.close()

    if len(osd) == 0:
        print >> sys.stderr, """\
Something's wrong. No fingerprints were found by %s.""" % sys.argv[0]
        sys.exit(1)

    print ">>> Writing OS DB dump to %s." % OS_DB_DUMP
    write_os_db_dump(osd, OS_DB_DUMP)
