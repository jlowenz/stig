import os
import os.path
import subprocess as p
import fileinput as fin
import pexpect as ex
import StringIO as sio
import string as s

class stig:
    def __init__(self, do_apply = False):
        self.do_apply = do_apply

    def blah(self):
        pass

def sudo(expr):
    return "gksudo -- " + expr

def cmd(expr, ret=0):
    return p.call(expr, shell=True) == ret

def get_results(expr):
    ret = ex.run(expr, withexitstatus=True)
    if ret[1] == 0:
        return ret[0]
    else:
        return None

def not_found(expr):
    ret = ex.run(expr,withexitstatus=True)
    return ret[0] == '' and ret[1] == 0

def verify_package(pkg_name, do_install=True):
    """ Check to see if a package is installed, and if not, install according to the argument do_install """
    print "Verifying package:", pkg_name
    pkg_check = os.system("dpkg --list | grep ^ii.*" + pkg_name)
    if pkg_check != 0 and do_install:        
        ret = p.call("gksudo -- apt-get install -y " + pkg_name, shell=True)
        return ret == 0
    else:
        return pkg_check == 0

def check_os_version():
    # Check the OS version first.  Meets a STIG requirement and if it's not a supported version for this lockdown script exit
    #
    # Rule-ID SV-27049r1 - OS must be a supported release
    #
    # Check if the OS is Ubuntu and is a supported ROGUE version
    #
    # Grab the OS version. Bend, fold, spindle, mutilate  - deteriorata - so that it can be verified
    #
    # First and foremost, using this script means you are using a supposted release for ROGUE
    # Second, this scipt is intended for ROGUE use and if the OS changes, so will this script.
    
    os_cmd_check = os.system('lsb_release -d')
    os_text_string = os.popen('lsb_release -d').read().split()
    os_text_version = os_text_string[2]
    os_text_version = os_text_version.strip()
    
    if os_cmd_check != 0:
        print 'Ubuntu version command failed. Not an Ubuntu OS or supported Ubuntu OS?\nExiting.'
        return False
        
    if (os_text_version != "12.04.4") and (os_text_version != "14.04"):
        print 'Found version ' + os_text_version
        print 'Unsupported version of Ubuntu detected.\nThis script supports Ubuntu 12.04.4 LTS and 14.04 LTS.\nExiting.\n'
        return False

    return True

def install_dependencies():
    # handle pexpect for this script?
    verify_package("python-pexpect")
    import pexpect

def update_packages():
    p.call("gksudo -- apt-get update", shell=True)

def sshd_running():
    return cmd("pidof sshd")

def replace_line(filename, pattern, replace):
    cmd(sudo("perl -pie 's/{0}/{1}/g' {2}".format(pattern,replace,filename)))

def install_and_configure_sshd():
    verify_package("openssh-server")
    if not cmd("grep -i '^protocol 2' /etc/ssh/sshd_config"):
        print "Updating sshd for protocol 2"
        replace_line("/etc/ssh/sshd_config", "^Protocol .*", "Protocol 2")
    
def remove_files(files):
    buf = sio.StringIO(files)
    lines = []
    for f in buf.readlines():
        ff = s.strip(f)
        lines.append(ff)
    lines = s.join(lines)
    print lines
    cmd(sudo("rm {0}".format(lines)))

def find_files():
    pass
