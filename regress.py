# Copyright 2012 Jeff Trawick, http://emptyhammock.com/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ConfigParser
import os
import socket
import subprocess
import sys

config = ConfigParser.RawConfigParser()
config.read('regress.cfg')

hn = socket.gethostname()
plat = sys.platform

section = "%s_%s" % (hn, plat)

bldcmd = config.get(section, 'BUILD').split(' ')
if config.has_option(section, 'HTTPD22_INSTALLS'):
    httpd22_installs = config.get(section, 'HTTPD22_INSTALLS').split(' ')
else:
    httpd22_installs = []

if config.has_option(section, 'HTTPD24_INSTALLS'):
    httpd24_installs = config.get(section, 'HTTPD24_INSTALLS').split(' ')
else:
    httpd24_installs = []

if sys.platform == 'win32':
    testcrash = '.\\testcrash.exe'
    testdiag = '.\\testdiag.exe'
else:
    testcrash = './testcrash'
    testdiag = './testdiag'

for httpd in httpd22_installs + httpd24_installs:
    print "Building for %s..." % (httpd)

    logfile = open("regress.log", "w")

    os.putenv('HTTPD', httpd)
    try:
        rc = subprocess.call(bldcmd, stdout=logfile, stderr=subprocess.STDOUT)
    except:
        print "couldn't run, error", sys.exc_info()[0]
        raise

    logfile.close()

    if rc != 0:
        print "rc:", rc
        sys.exit(1)

    print "Testing %s..." % (testcrash)

    logfile = open("regress.log", "w")
    try:
        rc = subprocess.call([testcrash], stdout=logfile, stderr=None, shell=False)
    except:
        print "couldn't run, error", sys.exc_info()[0]
        raise

    logfile.close()

    if sys.platform == 'win32':
        required_lines = ['Exception code:    EXCEPTION_ACCESS_VIOLATION']
    else:
        required_lines = ['Invalid memory address: 0xDEADBEEF']

    lines = open("regress.log").readlines()
    for rl in required_lines:
        if not rl + '\n' in lines:
            print "fail, required line >%s< not found in >%s<" % (rl, lines)
            assert False

    print "Testing %s..." % (testdiag)

    logfile = open("regress.log", "w")
    try:
        rc = subprocess.call([testdiag], stdout=logfile, stderr=None, shell=False)
    except:
        print "couldn't run, error", sys.exc_info()[0]
        raise

    logfile.close()

    required_lines = ['testdiag: ONELINER', 'y<x<w']

    lines = open("regress.log").readlines()
    for rl in required_lines:
        if not rl + '\n' in lines:
            print "fail, required line >%s< not found in >%s<" % (rl, lines)
            assert False
            assert False

