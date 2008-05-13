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

import sys
import os
import os.path
import re

import distutils.sysconfig
from distutils.core import setup
from distutils.command.install import install

from glob import glob
from stat import *

from zenmapCore.Version import VERSION
from zenmapCore.Name import APP_NAME, APP_DISPLAY_NAME, APP_WEB_SITE, APP_DOWNLOAD_SITE, NMAP_DISPLAY_NAME

# Directories for POSIX operating systems
# These are created after a "install" or "py2exe" command
# These directories are relative to the installation or dist directory
pixmaps_dir = os.path.join('share', 'pixmaps')
icons_dir = os.path.join('share', 'icons')
locale_dir = os.path.join('share', APP_NAME, 'locale')
config_dir = os.path.join('share', APP_NAME, 'config')
docs_dir = os.path.join('share', APP_NAME, 'docs')
misc_dir = os.path.join('share', APP_NAME, 'misc')

def mo_find(result, dirname, fnames):
    files = []
    for f in fnames:
        p = os.path.join(dirname, f)
        if os.path.isfile(p) and f.endswith(".mo"):
            files.append(p)
        
    if files:
        result.append((dirname, files))

################################################################################
# Installation variables

data_files = [ (pixmaps_dir, glob(os.path.join(pixmaps_dir, '*.svg')) +
                             glob(os.path.join(pixmaps_dir, '*.png'))),

               (config_dir, [os.path.join(config_dir, APP_NAME + '.conf')] +
                            [os.path.join(config_dir, 'scan_profile.usp')] +
                            [os.path.join(config_dir, APP_NAME + '_version')]),

               (misc_dir, glob(os.path.join(misc_dir, '*.dmp')) +
                          glob(os.path.join(misc_dir, '*.xml'))), 

               (icons_dir, glob(os.path.join('share', 'icons', '*.ico'))+
                           glob(os.path.join('share', 'icons', '*.png'))),

               (docs_dir, [os.path.join(docs_dir, 'help.html')])]

# Add i18n files to data_files list
os.path.walk(locale_dir, mo_find, data_files)

################################################################################
# Distutils subclasses

class my_install(install):
    def run(self):
        install.run(self)

        self.set_perms()
        self.set_modules_path()
        self.fix_paths()
        self.create_uninstaller()

    def create_uninstaller(self):
        uninstaller_filename = os.path.join(self.install_scripts, "uninstall_" + APP_NAME)
        uninstaller = """#!/usr/bin/env python
import os, os.path, sys

print
print '%(line)s Uninstall %(name)s %(version)s %(line)s'
print

answer = raw_input('Are you sure that you want to completly uninstall %(name)s %(version)s? \
(yes/no) ')

if answer != 'yes' and answer != 'y':
    sys.exit(0)

print
print '%(line)s Uninstalling %(name)s %(version)s... %(line)s'
print
""" % {'name':APP_DISPLAY_NAME, 'version':VERSION, 'line':'-'*10}

        for output in self.get_outputs():
            uninstaller += "print 'Removing %s...'\n" % output
            uninstaller += "if os.path.exists('%s'): os.remove('%s')\n" % (output,
                                                                         output)

        uninstaller += "print 'Removing uninstaller itself...'\n"
        uninstaller += "os.remove('%s')\n" % uninstaller_filename

        uninstaller_file = open(uninstaller_filename, 'w')
        uninstaller_file.write(uninstaller)
        uninstaller_file.close()

        # Set exec bit for uninstaller
        mode = ((os.stat(uninstaller_filename)[ST_MODE]) | 0555) & 07777
        os.chmod(uninstaller_filename, mode)

    def set_modules_path(self):
        app_file_name = os.path.join(self.install_scripts, APP_NAME)
        # Find where the modules are installed. distutils will put them in
        # self.install_lib, but that path can contain DESTDIR (--root option),
        # so we must strip it off if necessary.
        modules = self.install_lib
        if self.root is not None and modules.startswith(self.root):
            modules = modules[len(self.root):]

        re_sys = re.compile("^import sys$")

        ufile = open(app_file_name, "r")
        ucontent = ufile.readlines()
        ufile.close()

        uline = None
        for line in xrange(len(ucontent)):
            if re_sys.match(ucontent[line]):
                uline = line + 1
                break

        ucontent.insert(uline, "sys.path.append('%s')\n" % modules)

        ufile = open(app_file_name, "w")
        ufile.writelines(ucontent)
        ufile.close()

    def set_perms(self):
        re_bin = re.compile("(bin)")
        for output in self.get_outputs():
            if re_bin.findall(output):
                continue

            if os.path.isdir(output):
                os.chmod(output, S_IRWXU | \
                                 S_IRGRP | \
                                 S_IXGRP | \
                                 S_IROTH | \
                                 S_IXOTH)
            else:
                os.chmod(output, S_IRUSR | \
                                 S_IWUSR | \
                                 S_IRGRP | \
                                 S_IROTH)


    def fix_paths(self):
        """Replace some hardcoded paths to match where files were installed."""
        interesting_paths = {"CONFIG_DIR": os.path.join(self.prefix, config_dir),
                             "DOCS_DIR": os.path.join(self.prefix, docs_dir),
                             "LOCALE_DIR": os.path.join(self.prefix, locale_dir),
                             "MISC_DIR": os.path.join(self.prefix, misc_dir),
                             "PIXMAPS_DIR": os.path.join(self.prefix, pixmaps_dir),
                             "ICONS_DIR": os.path.join(self.prefix, icons_dir)}

        # Find and read the Paths.py file.
        pcontent = ""
        paths_file = os.path.join("zenmapCore", "Paths.py")
        installed_files = self.get_outputs()
        for f in installed_files:
            if re.findall("(%s)" % re.escape(paths_file), f):
                paths_file = f
                pf = open(paths_file)
                pcontent = pf.read()
                pf.close()
                break

        # Replace the path definitions.
        for path, replacement in interesting_paths.items():
            pcontent = re.sub("%s\s+=\s+.+" % path,
                              "%s = \"%s\"" % (path, replacement),
                              pcontent)

        # Write the modified file.
        pf = open(paths_file, "w")
        pf.write(pcontent)
        pf.close()


# setup can be called in different ways depending on what we're doing. (For
# example py2exe needs special handling.) These arguments are common between all
# the operations.
COMMON_SETUP_ARGS = {
    'name': APP_NAME,
    'license': 'GNU GPL (version 2 or later)',
    'url': APP_WEB_SITE,
    'download_url': APP_DOWNLOAD_SITE,
    'author': 'Adriano Monteiro & Cleber Rodrigues',
    'author_email': 'py.adriano@gmail.com, cleber@globalred.com.br',
    'maintainer': 'Adriano Monteiro',
    'maintainer_email': 'py.adriano@gmail.com',
    'description': """\
%s is the %s frontend.""" % (APP_DISPLAY_NAME, NMAP_DISPLAY_NAME),
    'long_description': """\
%s is an %s frontend \
that is really useful for advanced users and easy to be used by newbies.""" \
% (APP_DISPLAY_NAME, NMAP_DISPLAY_NAME),
    'version': VERSION,
    'scripts': [APP_NAME],
    'packages': ['zenmapCore', 'zenmapGUI', 'higwidgets'],
    'data_files': data_files,
}

# All of the arguments to setup are collected in setup_args.
setup_args = {}
setup_args.update(COMMON_SETUP_ARGS)

if 'py2exe' in sys.argv:
    # Windows- and py2exe-specific args.
    import py2exe

    WINDOWS_SETUP_ARGS = {
        'zipfile': None,
        'windows': [{"script": APP_NAME,
                     "icon_resources": [(1, os.path.join("share", "icons", "nmap-eye.ico"))]}],
        'options': {"py2exe": {
            "compressed": 1,
            "optimize":2,
            "packages":"encodings",
            "includes" : "\
pango,\
atk,\
gobject,\
pickle,\
bz2,\
encodings,\
encodings.*,\
cairo,\
pangocairo,\
atk,\
psyco\
"}}
    }

    setup_args.update(WINDOWS_SETUP_ARGS)
elif 'py2app' in sys.argv:
    # Args for Mac OS X and py2app.
    import py2app
    import shutil

    # py2app requires a ".py" suffix.
    extended_app_name = APP_NAME + ".py"
    shutil.copyfile(APP_NAME, extended_app_name)

    MACOSX_SETUP_ARGS = {
        'app': [extended_app_name],
        'options': {"py2app": {
            "packages": ["gobject", "gtk", "cairo"],
            "includes": ["atk", "pango", "pangocairo"],
            "argv_emulation": True,
            "compressed": True,
            "plist": "install_scripts/macosx/Info.plist",
            "iconfile": "install_scripts/macosx/zenmap.icns"
        }}
    }

    setup_args.update(MACOSX_SETUP_ARGS)
else:
    # Default args.
    DEFAULT_SETUP_ARGS = {
        'cmdclass': {'install': my_install},
    }

    setup_args.update(DEFAULT_SETUP_ARGS)

setup(**setup_args)
