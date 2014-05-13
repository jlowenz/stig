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
    
class v27051(STIG):
    def __init__(self):
        STIG.__init__(self, "(v27051) No host-based authentication")
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
    
class v39854(STIG):
    def __init__(self):
        STIG.__init__(self, "(v39854) No telnet daemon running")

    def check(self):
        return not service_running("telnet")
    
    def fix(self):
        disable_service("telnet", "telnetd")
    
class v44654(STIG):
    def __init__(self):
        STIG.__init__(self, "(v44654) No special privilege accounts")
        
    def check(self):
        self.pw = "/etc/passwd"
        return not (grep_file(self.pw, "^shutdown") or 
                    grep_file(self.pw, "^halt") or 
                    grep_file(self.pw, "^reboot"))

    def fix(self):
        if grep_file(self.pw, "^shutdown"):
            remove_user("shutdown")
        if grep_file(self.pw, "^halt"):
            remove_user("halt")
        if grep_file(self.pw, "^reboot"):
            remove_user("reboot")

class v39817(STIG):
    def __init__(self):
        STIG.__init__(self, "(v39817) SSH daemon must only use v2 protocol")
        self.fn = "/etc/ssh/sshd_config"
        
    def check(self):
        return grep_file(self.fn, "^Protocol 2$") and not grep_file(self.fn, "^Protocol 1$")

    def fix(self):
        install_and_configure_sshd()

class v44658(STIG):
    def __init__(self):
        STIG.__init__(self, "(v44658) NFS Server must have secure file locking")

    def check(self):
        running = service_running("nfs")
        insecure = False
        if running:
            insecure = p.call(sudo("exportfs -v | grep -ci insecure_locks"), shell=True) == 0
        return (not running) or (not insecure)
    
    def fix(self):
        return error("Must remove the insecure_locks option from nfs exports")
    

class v4382(STIG):
    def __init__(self):
        STIG.__init__(self, "(v4382) Admin accounts must not run web browser")
        self.paths = ["~root/.netscape","~root/.mozilla","~root/.config/google-chrome"]
        
    def check(self):
        used_browser = False
        for p in self.paths:
            used_browser = used_browser or dir_exists(os.path.expanduser(p))
        return not used_browser

    def fix(self):
        return error("Root user must not run web browser")

class v4387(STIG):
    def __init__(self):
        STIG.__init__(self, "(v4387) Anon FTP accounts cannot have functional shell")

    def check(self):
        ftp_account = grep_file("/etc/passwd", "^ftp")
        no_shell = True
        if ftp_account:
            no_shell = grep_file("/etc/passwd", "^ftp.*:/bin/false$")
        return (not ftp_account) or no_shell

    def fix(self):
        return error("Disable ftp account or set shell to /bin/false")

class v4399(STIG):
    def __init__(self):
        STIG.__init__(self, "(v4399) No UDP for NIS (or NO NIS)")

    def check(self):
        has_pkg = verify_package("nis", do_install=False)
        using_udp = p.call("rpcinfo -p | grep yp | grep udp", shell=True) == 0
        return (not has_pkg) or (not using_udp)
    
    def fix(self):
        remove_package("nis")
        return error("Disable and remove NIS or configure the system to not use UDP")

class v27435(STIG):
    def __init__(self):
        STIG.__init__(self, "(v27435) RSH daemon cannot be running")
        self.pkgs = ["rsh-redone-server",
                     "rsh-server",
                     "lsh-server",
                     "sbrsh",
                     "sbrshd"]
        
    def check(self):
        rsh_is_ssh = get_results("rsh -V").startswith("OpenSSH")
        rsh_not_running = not service_running("rsh")
        bad_pkg_installed = False
        for p in self.pkgs:
            bad_pkg_installed = bad_pkg_installed or verify_package(p, do_install=False)
        return (rsh_is_ssh or rsh_not_running) and not bad_pkg_installed

    def fix(self):
        disable_service("rsh")
        for p in self.pkgs:
            if verify_package(p, do_install=False):
                remove_package(p)
        
class v27438(STIG):
    def __init__(self):
        STIG.__init__(self, "(v27438) Rexec daemon cannot be running")

    def check(self):
        return not service_running("rexec")        

    def fix(self):
        disable_service("rexec")

class v50403(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50403) Rlogin service must not be running")

    def check(self):
        return not service_running("rlogin")
    
    def fix(self):
        disable_service("rlogin")

class v50415(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50415) SSH daemon must not allow authentication with empty password")
        self.fn = "/etc/ssh/sshd_config"

    def check(self):
        disallow_empty_pw = grep_file(self.fn, "^PermitEmptyPasswords no")
        return disallow_empty_pw

    def fix(self):        
        replace_line(self.fn, "^PermitEmptyPasswords", "PermitEmptyPasswords no")
