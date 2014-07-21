# Copyright 2012, 2014 Jeff Trawick, http://emptyhammock.com/
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
import errno
import os
import shutil
import socket
import subprocess
import sys
import time

if sys.platform == 'win32':
    log_ext = '.log'
    httpd_exe = 'httpd.exe'
    testcrash = '.\\testcrash.exe'
    testdiag = '.\\testdiag.exe'
else:
    log_ext = '_log'
    httpd_exe = 'apachectl'
    testcrash = './testcrash'
    testdiag = './testdiag'


def add_to_log(arg):
    logfile = open("regress.log", "a")
    print >> logfile, arg
    logfile.close()


def get_cmd_output(args):
    logfilename = "regress.tmp"
    logfile = open(logfilename, "w")
    try:
        rc = subprocess.call(args, stdout=logfile, stderr=subprocess.STDOUT)
    except:
        msg = "couldn't run, error", sys.exc_info()[0]
        raise Exception(msg)
    logfile.close()
    msgs = open(logfilename).readlines()
    os.unlink(logfilename)
    return rc, msgs


def is_active():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    active = False
    try:
        s.connect(('127.0.0.1', 10080))
        active = True
    except:
        pass
    s.close()
    return active


def simple_request(addr, uri, req):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect(addr)
    s.send(req)

    rsp = ''
    while True:
        try:
            tmprsp = s.recv(4096)
        except socket.error, e:
            if e.errno == errno.ECONNRESET:
                tmprsp = None
            else:
                raise
        if tmprsp:
            rsp += tmprsp
        else:
            break

    s.close()

    add_to_log("Response from %s request:" % uri)
    add_to_log(rsp)

    return rsp


def test_httpd(section, httpd, skip_startstop):
    if is_active():
        raise Exception("some httpd is active, but we haven't started any server yet")

    wku_log = os.path.join(httpd, 'logs', 'whatkilledus' + log_ext)
    err_log = os.path.join(httpd, 'logs', 'error' + log_ext)

    print section, httpd

    if os.path.exists(err_log):
        os.unlink(err_log)

    conf_d = '%s/conf/conf.d/' % httpd
    if not os.path.isdir(conf_d):
        raise Exception("%s does not exist or is not a directory" % conf_d)

    shutil.copy('diag.conf', conf_d)

    (rc, version_output) = get_cmd_output([os.path.join(httpd, 'bin', httpd_exe), '-v'])
    add_to_log(version_output)
    print version_output[0],
    if 'Apache/2.2' in version_output[0]:
        httpdver = 22
    elif 'Apache/2.4' in version_output[0]:
        httpdver = 24
    elif 'Apache/2.5' in version_output[0]:
        # at least until it makes a real difference
        httpdver = 24
    else:
        raise Exception("Unknown server version (%s)" % version_output[0])

    if not skip_startstop:
        if sys.platform == 'win32':
            print 'Start httpd from install %s now...' % httpd
        else:
            (rc, msgs) = get_cmd_output([os.path.join(httpd, 'bin', 'apachectl'), 'start'])
            if rc != 0:
                print 'httpd start failed:'
                print msgs
                raise Exception('httpd start failed')
            add_to_log(msgs)

        while not is_active():
            print '.',
            time.sleep(1)
        print

    simple_request(('127.0.0.1', 10080), '/backtrace/',
                   'GET /backtrace/ HTTP/1.0\r\nConnection: close\r\nHost: 127.0.0.1\r\n\r\n')

    if os.path.exists(wku_log):
        os.unlink(wku_log)

    rsp = simple_request(('127.0.0.1', 10080), '/crash/',
                         'GET /crash/foo\1\2\3/?queryarg=private HTTP/1.0\r\nConnection: close\r\n' +
                         'Host: 127.0.0.1\r\nX-Jeff: Trawick\r\nFooHdr: FooVal\r\nBarHdr: \1\2\3\4\5\6\7\r\n\r\n')

    crashing_pid = rsp.split(' ')[-1][:-4]
    add_to_log("Pid that crashed: >%s<" % crashing_pid)

    log = open(wku_log).readlines()
    add_to_log("%s:" % wku_log)
    add_to_log(log)

    pid_found = False
    foohdr_found = False
    barhdr_found = False
    x_jeff_found = False
    obscured_query_found = False
    client_conn_found = False
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
        elif 'Request line (unparsed):' in l:
            print "This line should not appear:", l
            assert False
        elif 'GET /crash/foo%01%02%03/?****************' in l:
            obscured_query_found = True
        elif '->127.0.0.1:10080' in l:
            client_conn_found = True

    assert pid_found
    assert foohdr_found
    assert barhdr_found
    assert x_jeff_found
    assert obscured_query_found
    assert client_conn_found

    time.sleep(10)  # child just crashed, may take a while for process to dump core

    if not skip_startstop:
        if sys.platform == 'win32':
            print 'Stop httpd from install %s now...' % httpd
        else:
            (rc, msgs) = get_cmd_output([os.path.join(httpd, 'bin', 'apachectl'), 'stop'])
            if rc != 0:
                print 'httpd stop failed:'
                print msgs
                raise Exception('httpd stop failed')
        while is_active():
            print '.',
            time.sleep(1)
        print
        time.sleep(5)

    errlog = open(err_log).readlines()
    add_to_log("%s:" % err_log)
    add_to_log(errlog)

    wku_version_found = False
    bt_version_found = False
    bt_eyecatcher_found = False
    bt_backtrace_found = False
    child_pid_exit_found = False
    httpd_terminated_found = False

    for l in errlog:
        if 'seg fault or similar nasty error' in l:
            print l
            assert False
        elif 'mod_backtrace v2.01 from' in l:
            bt_version_found = True
        elif 'mod_whatkilledus v2.01 from' in l:
            wku_version_found = True
        elif '---MoD_bAcKtRaCe---' in l:
            bt_eyecatcher_found = True
            if httpdver == 24:
                if '<ap_run_handler<ap_invoke_handler<' in l:
                    bt_backtrace_found = True
                elif 'diag_backtrace_init<diag_backtrace_init' in l:
                    bt_backtrace_found = True
                elif 'backtrace_handler<ap_run_handler' in l:  # Apachelounge build with no .pdb files
                    bt_backtrace_found = True
                elif ' [0x' in l and '<0x' in l:  # Ubuntu 11-64
                    bt_backtrace_found = True
        elif httpdver == 22 and 'mod_backtrace: ' in l and '<ap_' in l:
            bt_backtrace_found = True
        elif 'child pid ' in l and 'exit signal' in l:
            exited_pid = l[l.find('child pid '):].split()[2]
            if exited_pid == crashing_pid:
                child_pid_exit_found = True
            else:
                print "Unexpected crashing child:", l
                assert False
        elif 'child process exited with status ' in l and 'Restarting' in l:
            # this is Windows; the child pid isn't included in the message :(
            child_pid_exit_found = True
        elif 'caught SIGTERM' in l:
            httpd_terminated_found = True
        elif 'Parent: Child process exited successfully' in l:
            # this is Windows; this is the last [notice] message with 2.2
            httpd_terminated_found = True

    assert wku_version_found
    assert bt_version_found
    assert bt_eyecatcher_found
    assert bt_backtrace_found
    assert child_pid_exit_found
    assert httpd_terminated_found


def main():
    if os.path.exists("regress.log"):
        os.unlink("regress.log")

    config = ConfigParser.RawConfigParser()
    config.read('regress.cfg')

    hn = socket.gethostname()
    plat = sys.platform

    section = "%s_%s" % (hn, plat)

    add_to_log('Starting tests on ' + section + ' at ' + time.ctime())

    (rc, msgs) = get_cmd_output(['hg', 'identify', '-ni'])
    add_to_log('Code version:')
    add_to_log(msgs)

    bldcmd = config.get(section, 'BUILD').split(' ')
    if config.has_option(section, 'HTTPD22_INSTALLS'):
        httpd22_installs = config.get(section, 'HTTPD22_INSTALLS').split(' ')
    else:
        httpd22_installs = []

    if config.has_option(section, 'HTTPD24_INSTALLS'):
        httpd24_installs = config.get(section, 'HTTPD24_INSTALLS').split(' ')
    else:
        httpd24_installs = []

    skip_bld = 0
    skip_startstop = 0

    for httpd in httpd22_installs + httpd24_installs:

        if not skip_bld:
            print "Building for %s..." % httpd
            add_to_log("Building for %s..." % httpd)

            os.putenv('HTTPD', httpd)
            (rc, build_msgs) = get_cmd_output(bldcmd)

            add_to_log(build_msgs)
            add_to_log("Build rc: %d" % rc)

            if rc != 0:
                print "rc:", rc
                sys.exit(1)

        print "Testing %s..." % testcrash
        add_to_log("Testing %s..." % testcrash)

        (rc, msgs) = get_cmd_output([testcrash])
        add_to_log(msgs)
        add_to_log("testcrash rc %d" % rc)

        if sys.platform == 'win32':
            required_lines = ['Exception code:    EXCEPTION_ACCESS_VIOLATION']
        else:
            required_lines = ['Invalid memory address: 0xDEADBEEF']

        for rl in required_lines:
            if not rl + '\n' in msgs:
                print "fail, required line >%s< not found in >%s<" % (rl, msgs)
                assert False

        print "Testing %s..." % testdiag
        add_to_log("Testing %s..." % testdiag)

        (rc, msgs) = get_cmd_output([testdiag])
        add_to_log(msgs)
        add_to_log("testdiag rc %d" % rc)

        required_lines = ['testdiag: ONELINER', 'y<x<w']

        for rl in required_lines:
            if not rl + '\n' in msgs:
                print "fail, required line >%s< not found in >%s<" % (rl, msgs)
                assert False

        test_httpd(section, httpd, skip_startstop)

if __name__ == '__main__':
    main()
