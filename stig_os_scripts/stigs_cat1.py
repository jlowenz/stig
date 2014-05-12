from ubuntu import *
import os
import subprocess as p

# so for each fix class, we have a check and fix method

Pass = True
Fail = False

def status(v):
    if v:
        return "Pass"
    else:
        return "Fail"

class STIG(object):
    def __init__(self, desc):
        self.desc = desc
        self.status = Fail
        
    def __str__(self):
        return self.desc + ": " + status(self.check())

    def error(self, msg):
        self.message = msg
        self.status = Fail
        return msg

    def success(self, msg):
        self.message = msg
        self.status = Pass
        return msg

    def check(self):
        print self.desc + ": checking..."
        return False
    
    def fix(self):
        print self.desc + ": fixing..."
        return False

class v1046(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1046) Check for root passwords in clear text")
        
    def check(self):
        return not (cmd("last -w | grep -ci '^root'") and not sshd_running())
    
    def fix(self):        
        if not self.check():
            # install and configure sshd
            install_and_configure_sshd()
        return self.success("sshd installed and configured")
        
        

class v11940(STIG):
    def __init__(self):
        STIG.__init__(self,"(v11940) Operating system is supported release")
        
    def check(self):
        return check_os_version()

    def fix(self):
        return self.error("Cannot be fixed by this script")
    
class v11988(STIG):
    def __init__(self):
        STIG.__init__(self, "(v11988) No host-based authentication")
        self.homes = "find /home -name \*.[rs]hosts"
        self.etc = "find /etc -regex .*s*hosts.equiv"
    
    def check(self):
        homes = not_found(sudo(self.homes))
        etc = not_found(sudo(self.etc))
        return homes and etc

    def fix(self):
        if not self.check():
            homes = get_results(sudo(self.homes))
            etc = get_results(sudo(self.etc))
            remove_files(homes)
            remove_files(etc)
    

