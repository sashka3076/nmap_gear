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

# This file contains the definitions of two main classes:
# NmapCommand represents and runs an Nmap command line. CommandConstructor
# builds a command line string from textual option descriptions.

import sys
import os
import re
import threading
import unittest

from tempfile import mktemp
from types import StringTypes
try:
    from subprocess import Popen, PIPE
except ImportError, e:
    raise ImportError(str(e) + ".\n" + _("Python 2.4 or later is required."))

import zenmapCore.Paths
from zenmapCore.NmapOptions import NmapOptions
from zenmapCore.OptionsConf import options_file
from zenmapCore.UmitLogging import log
from zenmapCore.I18N import _
from zenmapCore.UmitConf import PathsConfig

# This variable is used in the call to Popen. It determines whether the
# subprocess invocation uses the shell or not. If it is False on Unix, the nmap
# process is started with execve and a list of arguments, which is what we want.
# (Indeed it fails when shell_state = True because it tries to exec
# ['sh', '-c', 'nmap', '-v', ...], which is wrong.) So normally we would want
# shell_state = False. But if shell_state = False on Windows, a big ugly black
# shell window opens whenever a scan is run, at least under py2exe. So we define
# shell_state = True on Windows only. Windows doesn't have exec, so it runs the
# command basically the same way regardless of shell_state.
shell_state = (sys.platform == "win32")

# The path to the nmap executable as used by Popen.
# Find the value from configuation file paths nmap_command_path
# to use for the location of the nmap executable.
# (The bug that nmap_command_path is not used from zenmap.conf has been resolved.)

nmap_paths = PathsConfig()
nmap_command_path = nmap_paths.nmap_command_path

log.debug(">>> Platform: %s" % sys.platform)
log.debug(">>> Nmap command path: %s" % nmap_command_path)

def split_quoted(s):
    """Like str.split, except that no splits occur inside quoted strings, and
    quoted strings are unquoted."""
    return [x.replace("\"", "") for x in re.findall('((?:"[^"]*"|[^"\s]+)+)', s)]

class NmapCommand(object):
    """This class represents an Nmap command line. It is responsible for
    starting, stopping, and returning the results from a command-line scan. A
    command line is represented as a backing string in the variable command but
    it is split into a list of arguments in the variable _command for
    execution."""

    def __init__(self, command=None):
        """Initialize an Nmap command. This creates temporary files for
        redirecting the various types of output and sets the backing
        command-line string."""
        self.xml_output = mktemp()
        self.normal_output = mktemp()
        self.stdout_output = mktemp()
        self.stderr_output = mktemp()

        log.debug(">>> Created temporary files:")
        log.debug(">>> XML OUTPUT: %s" % self.xml_output)
        log.debug(">>> NORMAL OUTPUT: %s" % self.normal_output)
        log.debug(">>> STDOUT OUTPUT: %s" % self.stdout_output)
        log.debug(">>> STDERR OUTPUT: %s" % self.stderr_output)

        # Pre-create the output files. This had the comment "Avoid troubles
        # while running at Windows" but it is unnecessary.
        open(self.xml_output,'w').close()
        open(self.normal_output,'w').close()
        open(self.stdout_output,'w').close()
        open(self.stderr_output,'w').close()

        self.command_process = None
        self.command_buffer = ""
        self.command_stderr = ""

        if command:
            self.command = command

    def get_command(self):
        """command is a property of this class; this is the getter. It returns
        the list self._command."""
        # FIXME: don't allow self._command to be a string.
        if type(self._command) == type(""):
            return self._command.split()
        return self._command

    def set_command(self, command):
        """command is a property of this class; this is the setter. It calls
        _verify to split the command line into the list self._command."""
        self._command = self._verify(command)

    def _verify(self, command):
        """This misnamed method sanitizes command and splits it into a list
        suitable for execution."""
        command = self._remove_double_space(command)
        command = self._verify_output_options(command)
        command[0] = nmap_command_path

        return command

    def _verify_output_options(self, command):
        """Remove comments from command, add output options, and return the
        command split up into a list."""
        # FIXME: don't allow command to be a list.
        if type(command) == type([]):
            command = " ".join(command)

        # Removing comments from command
        for comment in re.findall('(#.*)', command):
            command = command.replace(comment, '')

        # Removing output options that user may have set away from command
        found = re.findall('(-o[XGASN]{1}) {0,1}', command)

        # Split back into individual options, honoring double quotes.
        splited = split_quoted(command)

        if found:
            for option in found:
                pos = splited.index(option)
                del(splited[pos+1])
                del(splited[pos])

        # Saving the XML output to a temporary file
        splited.append('-oX')
        splited.append('%s' % self.xml_output)

        # Saving the Normal output to a temporary file
        splited.append('-oN')
        splited.append('%s' % self.normal_output)

        # Disable runtime interaction feature
        #splited.append("--noninteractive")


        # Redirecting output
        #splited.append('>')
        #splited.append('%s' % self.stdout_output)

        return splited

    def _remove_double_space(self, command):
        """Coalesce multiple space characters in command into single spaces."""
        # FIXME: Don't allow command to be a list.
        if type(command) == type([]):
            command = " ".join(command)

        # The first join + split ensures to remove double spaces on lists like this:
        # ["nmap    ", "-T4", ...]
        # And them, we must return a list of the command, that's why we have the second split
        return " ".join(command.split()).split()

    def close(self):
        """Close and remove temporary output files used by the command."""
        self._stdout_handler.close()
        self._stderr_handler.close()

        os.remove(self.xml_output)
        os.remove(self.normal_output)
        os.remove(self.stdout_output)

    def kill(self):
        """Kill the nmap subprocess."""
        log.debug(">>> Killing scan process %s" % self.command_process.pid)

        if sys.platform != "win32":
            try:
                from signal import SIGKILL
                os.kill(self.command_process.pid, SIGKILL)
            except:
                pass
        else:
            try:
                # Not sure if this works. Must research a bit more about this
                # subprocess's method to see how it works.
                # In the meantime, this should not raise any exception because
                # we don't care if it killed the process as it never killed it anyway.
                from subprocess import TerminateProcess
                TerminateProcess(self.command_process._handle, 0)
            except:
                pass

    def get_path(self):
        """Return a value for the PATH environment variable that is appropriate
        for the current platform. It will be the PATH from the environment plus
        possibly some platform-specific directories."""
        path_env = os.getenv("PATH")
        if path_env is None:
            search_paths = []
        else:
            search_paths = path_env.split(os.pathsep)
        for path in zenmapCore.Paths.get_extra_executable_search_paths():
            if path not in search_paths:
                search_paths.append(path)
        return os.pathsep.join(search_paths)

    def run_scan(self):
        """Run the command that has been set."""
        if not self.command:
            raise Exception("You have no command to run! Please, set the command \
before trying to start scan!")

        #self.command_process = Popen(self.command, bufsize=1, stdin=PIPE,
        #                             stdout=PIPE, stderr=PIPE)
        
        # Because of problems with Windows, I passed only the file descriptors to \
        # Popen and set stdin to PIPE
        # Python problems... Cross-platform execution of process should be improved
        
        self._stdout_handler = open(self.stdout_output, "w+")
        self._stderr_handler = open(self.stderr_output, "w+")
        
        search_paths = self.get_path()
        env = dict(os.environ)
        env["PATH"] = search_paths
        log.debug("PATH=%s" % env["PATH"])

        self.command_process = Popen(self.command, bufsize=1,
                                     stdin=PIPE,
                                     stdout=self._stdout_handler.fileno(),
                                     stderr=self._stderr_handler.fileno(),
                                     shell=shell_state,
                                     env=env)

    def scan_state(self):
        """Return the current state of a running scan. A return value of True
        means the scan is running and a return value of False means the scan
        subprocess completed successfully. If the subprocess terminated with an
        error an exception is raised. The scan must have been started with
        run_scan before calling this method."""
        if self.command_process == None:
            raise Exception("Scan is not running yet!")

        state = self.command_process.poll()

        if state == None:
            return True # True means that the process is still running
        elif state == 0:
            return False # False means that the process had a successful exit
        else:
            self.command_stderr = self.get_error()
            
            log.critical("An error occurred during the scan execution!")
            log.critical('%s' % self.command_stderr)
            log.critical("Command that raised the exception: '%s'" % " ".join(self.command))
            
            raise Exception("An error occurred during the scan execution!\n'%s'" % \
                            self.command_stderr)

    def scan_progress(self):
        """Should return a tuple with the stage and status of the scan execution
        progress. Will work only when the runtime interaction problem is solved.
        """
        pass

    def get_raw_output(self):
        """Return the stdout of the nmap subprocess. This is the same as
        get_output."""
        raw_desc = open(self.stdout_output, "r")
        raw_output = raw_desc.readlines()
        
        raw_desc.close()
        return "".join(raw_output)

    def get_output(self):
        """Return the stdout of the nmap subprocess. This is the same as
        get_raw_output."""
        output_desc = open(self.stdout_output, "r")
        output = output_desc.read()

        output_desc.close()
        return output

    def get_output_file(self):
        """Return the name of the stdout output file."""
        return self.stdout_output

    def get_normal_output(self):
        """Return the normal (-oN) output of the nmap subprocess."""
        normal_desc = open(self.normal_output, "r")
        normal = normal_desc.read()

        normal_desc.close()
        return normal

    def get_normal_output_file(self):
        """Return the name of the normal (-oN) output file."""
        return self.normal_output

    def get_xml_output(self):
        """Return the XML (-oX) output of the nmap subprocess."""
        xml_desc = open(self.xml_output, "r")
        xml = xml_desc.read()

        xml_desc.close()
        return xml

    def get_xml_output_file(self):
        """Return the name of the XML (-oX) output file."""
        return self.xml_output

    def get_error(self):
        """Return the stderr output of the nmap subprocess."""
        error_desc = open(self.stderr_output, "r")
        error = error_desc.read()

        error_desc.close()
        return error

    command = property(get_command, set_command)
    # FIXME: This is a class-level variable but it should be an instance
    # variable. Is it used?
    _command = None

class CommandConstructor:
    """This class builds a string representing an Nmap command line from textual
    option descriptions such as 'Aggressive Options' or 'UDP Scan'
    (corresponding to -A and -sU respectively). The name-to-option mapping is
    done by the NmapOptions class. Options are stored in a dict that maps the
    option name to a tuple containing its arguments and "level." The level is
    the degree of repetition for options like -v that can be given more than
    once."""

    def __init__(self, options = {}):
        """Initialize a command line using the given options. The options are
        given as a dict mapping option names to arguments."""
        self.options = {}
        self.option_profile = NmapOptions(options_file)
        for k, v in options.items():
            self.add_option(k, v, False)

    def add_option(self, option_name, args=[], level=False):
        """Add an option to the command line. Only one of args and level can be
        defined. If both are defined, level takes precedence and args is
        ignored."""
        self.options[option_name] = (args, level)

    def remove_option(self, option_name):
        """Remove an option from the command line."""
        if option_name in self.options.keys():
            del(self.options[option_name])

    def get_command(self, target):
        """Return the contructed command line as a plain string."""
        splited = ['%s' % nmap_command_path]

        for option_name in self.options:
            option = self.option_profile.get_option(option_name)
            args, level = self.options[option_name]

            if type(args) in StringTypes:
                args = [args]

            if level:
                splited.append((option['option']+' ')*level)
            elif args:
                args = tuple (args)
                splited.append(option['option'] % args[0])
            else:
                splited.append(option['option'])
            
        splited.append(target)
        return ' '.join(splited)

    def get_options(self):
        """Return the options used in the command line, as a dict mapping
        options names to arguments. The level, if any, is discarded."""
        return dict([(k, v[0]) for k, v in self.options.items()])

# FIXME: This class is unused. Delete it.
class CommandThread(threading.Thread):
    def __init__(self, command):
        self._stop_event = threading.Event()
        self._sleep = 1.0
        threading.Thread.__init__(self)
        self.command = command

    def run(self):
        #self.command_result = os.popen3(self.command)
        self.command_result = os.system(self.command)

    def join(self, timeout=None):
        self._stop_event.set()
        threading.Thread.join(self, timeout)


##############
# Exceptions #
##############

# FIXME: All these exceptions are unused. Delete them.

class WrongCommandType(Exception):
    def __init__(self, command):
        self.command = command

    def __str__(self):
        print "Command must be of type string! Got %s instead." % str(type(self.command))

class OptionDependency(Exception):
    def __init__(self, option, dependency):
        self.option = option
        self.dependency = dependency
    
    def __str__(self):
        return "The given option '%s' has a dependency not commited: %s" %\
               (self.option, self.dependency)

class OptionConflict(Exception):
    def __init__(self, option, option_conflict):
        self.option = option
        self.option_conflict = option_conflict
    
    def __str__(self):
        return "The given option '%s' is conflicting with '%s'" %\
               (self.option, self.option_conflict)

class NmapCommandError(Exception):
    def __init__(self, command, error):
        self.error = error
        self.command = command
    
    def __str__(self):
        return """An error occouried while trying to execute nmap command.

ERROR: %s
COMMAND: %s
""" % (self.error, self.command)



class SplitQuotedTest(unittest.TestCase):
    """A unittest class that tests the split_quoted function."""

    def test_split(self):
        self.assertEqual(split_quoted(''), [])
        self.assertEqual(split_quoted('a'), ['a'])
        self.assertEqual(split_quoted('a b c'), 'a b c'.split())

    def test_quotes(self):
        self.assertEqual(split_quoted('a "b" c'), ['a', 'b', 'c'])
        self.assertEqual(split_quoted('a "b c"'), ['a', 'b c'])
        self.assertEqual(split_quoted('a "b c""d e"'), ['a', 'b cd e'])
        self.assertEqual(split_quoted('a "b c"z"d e"'), ['a', 'b czd e'])

# Testing module functionality! ;-)
if __name__ == '__main__':
    #command = CommandConstructor ('option_profile.uop')
    #print 'Aggressive options:', command.add_option ('Aggressive Options')
    #print 'UDP Scan:', command.add_option ('Version Detection')
    #print 'UDP Scan:', command.add_option ('UDP Scan')
    #command.add_option ('Idle Scan', ['10.0.0.138'])
    #command.add_option ('UDP Scan')
    #command.add_option ('ACK scan')
    #command.remove_option ('Idle Scannn')
    
    #print command.get_command ('localhost')
    #print command.get_command ('localhost')
    #print command.get_command ('localhost')
    
    #from time import sleep
    
    #nmap = NmapCommand (command)
    #executando = nmap.execute_nmap_command ()
    #print nmap.command
    #while executando[0].isAlive ():
    #    print open(executando[3]).read()
    #    sleep (1)
    #print open(executando[3]).read()

    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(SplitQuotedTest))

    scan = NmapCommand('%s -T4 -iL "/home/adriano/umit/test/targets\ teste"' % nmap_command_path)
    scan.run_scan()

    while scan.scan_state():
        print ">>>", scan.get_normal_output()
    print "Scan is finished!"
