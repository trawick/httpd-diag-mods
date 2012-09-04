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
import shutil
import socket
import subprocess
import sys
import time

if sys.platform == 'win32':
    log_ext = '.log'
else:
    log_ext = '_log'

def test_httpd(section, httpd, skip_startstop):
    wku_log = os.path.join(httpd, 'logs', 'whatkilledus' + log_ext)
    err_log = os.path.join(httpd, 'logs', 'error' + log_ext);

    print section, httpd

    if os.path.exists(err_log):
        os.unlink(err_log)

    shutil.copy('diag.conf', '%s/conf/conf.d/' % (httpd))

    if not skip_startstop:
        if sys.platform == 'win32':
            print 'Start httpd from install %s now...' % (httpd)
        else:
            try:
                rc = subprocess.call([os.path.join(httpd, 'bin', 'apachectl'), 'start'])
            except:
                print "couldn't run, error", sys.exc_info()[0]
                raise
        time.sleep(10);

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect(('127.0.0.1', 10080))
    s.send('GET /backtrace/ HTTP/1.0\r\nConnection: close\r\nHost: 127.0.0.1\r\n\r\n')

    rsp = ''
    while True:
        tmprsp = s.recv(4096)
        if tmprsp:
            rsp += tmprsp
        else:
            break

    s.close()

    print "Response:"
    print rsp

    if os.path.exists(wku_log):
        os.unlink(wku_log)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect(('127.0.0.1', 10080))
    s.send('GET /crash/ HTTP/1.0\r\nConnection: close\r\nHost: 127.0.0.1\r\nX-Jeff: Trawick\r\nFooHdr: FooVal\r\nBarHdr: \1\2\3\4\5\6\7\r\n\r\n')

    rsp = ''
    while True:
        try:
            tmprsp = s.recv(1)
            if tmprsp:
                rsp += tmprsp
            else:
                break
        except:
            break

    s.close()

    print "Response:"
    print rsp

    crashing_pid = rsp.split(' ')[-1][:-4]
    print "Pid that crashed: >%s<" % crashing_pid

    log = open(wku_log).readlines()
    print log

    pid_found = False
    foohdr_found = False
    barhdr_found = False
    x_jeff_found = False
    for l in log:
        if 'Process id:' in l:
            tpid = l.split()[2]
            if tpid == crashing_pid:
                pid_found = True
            else:
                print "Unexpected pid >%s<" % tpid
        elif 'FooHdr:FooVal' in l:
            foohdr_found = True
        elif 'BarHdr:%01%02%03%04%05%06%07' in l:
            barhdr_found = True
        elif 'X-Jeff:*******' in l:
            x_jeff_found = True

    assert pid_found
    assert foohdr_found
    assert barhdr_found
    assert x_jeff_found

    if not skip_startstop:
        if sys.platform == 'win32':
            print 'Stop httpd from install %s now...' % (httpd)
        else:
            try:
                rc = subprocess.call([os.path.join(httpd, 'bin', 'apachectl'), 'stop'])
            except:
                print "couldn't run, error", sys.exc_info()[0]
                raise
        time.sleep(10);

    errlog = open(err_log).readlines()
    print errlog

    wku_version_found = False
    bt_version_found = False
    bt_eyecatcher_found = False
    child_pid_exit_found = False
    httpd_terminated_found = False

    for l in errlog:
        if 'seg fault or similar nasty error' in l:
            print l
            assert False
        elif 'mod_backtrace v2.00 from' in l:
            bt_version_found = True
        elif 'mod_whatkilledus v2.00 from' in l:
            wku_version_found = True
        elif '---MoD_bAcKtRaCe---' in l:
            bt_eyecatcher_found = True
        elif 'child pid ' in l and 'exit signal' in l:
            exited_pid = l[l.find('child pid '):].split()[2]
            if exited_pid == crashing_pid:
                child_pid_exit_found = True
            else:
                print "Unexpected crashing child:", l
                assert False
        elif 'caught SIGTERM' in l:
            httpd_terminated_found = True

    assert wku_version_found
    assert bt_version_found
    assert bt_eyecatcher_found
    assert child_pid_exit_found
    assert httpd_terminated_found

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

skip_bld = 0
skip_startstop = 0

for httpd in httpd22_installs + httpd24_installs:

    if not skip_bld:
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

    test_httpd(section, httpd, skip_startstop)
