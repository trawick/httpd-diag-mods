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

for httpd in httpd22_installs + httpd24_installs:
    print "Building for %s..." % (httpd)

    os.putenv('HTTPD', httpd)
    try:
        rc = subprocess.call(bldcmd)
    except:
        print "couldn't run, error", sys.exc_info()[0]
        raise

    if rc != 0:
        print "rc:", rc
        sys.exit(1)
