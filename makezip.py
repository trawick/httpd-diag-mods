import os
import string
import subprocess
import sys

import diag_version

source_files = ['Makefile', 'makefile.win32', '*.c', '*.h']
meta_files = ['CHANGES.txt', 'LICENSE.txt', 'NOTICE.txt', 'README.txt']
bin_files = ['dist']

dirname = 'wku_bt-%s' % diag_version.version

if os.path.exists(dirname):
    raise Exception("%s should not already exist" % dirname)

if os.path.exists(dirname + '.zip'):
    raise Exception("zip should not already exist")

os.mkdir(dirname, 0755)

cmd = ['cp', '-pR'] + source_files + meta_files + bin_files + [dirname]

print cmd

cmd = string.join(cmd)
print cmd

try:
    rc = subprocess.call(cmd, shell=True)
except:
    print "couldn't run, error", sys.exc_info()[0]
    raise

if rc != 0:
    print "rc:", rc
    sys.exit(1)

try:
    rc = subprocess.call(['zip', '-r', '%s.zip' % dirname, dirname])
except:
    print "couldn't run, error", sys.exc_info()[0]
    raise

if rc != 0:
    print "rc:", rc
    sys.exit(1)
