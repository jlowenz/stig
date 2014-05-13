from ubuntu import *
import stig_functions
import os
import subprocess as p
import StringIO as sio

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
        self.homes = "find /home -regex .*\\.[rs]hosts"
        self.etc = "find /etc -regex .*s*hosts.equiv"
    
    def check(self):
        homes = not_found(sudo(self.homes))
        etc = not_found(sudo(self.etc))
        print homes, etc
        return homes and etc

    def fix(self):
        if not self.check():
            homes = unpack_lines(get_results(sudo(self.homes)))
            etc = unpack_lines(get_results(sudo(self.etc)))
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
        return self.error("Must remove the insecure_locks option from nfs exports")
    

class v4382(STIG):
    def __init__(self):
        STIG.__init__(self, "(v4382) Admin accounts must not run web browser")
        self.paths = ["~root/.netscape","~root/.mozilla","~root/.config/google-chrome"]
        
    def check(self):
        used_browser = False
        for p in self.paths:
            used_browser = used_browser or exists(os.path.expanduser(p))
        return not used_browser

    def fix(self):
        return self.error("Root user must not run web browser")

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
        return self.error("Disable ftp account or set shell to /bin/false")

class v4399(STIG):
    def __init__(self):
        STIG.__init__(self, "(v4399) No UDP for NIS (or NO NIS)")

    def check(self):
        has_pkg = verify_package("nis", do_install=False)
        using_udp = p.call("rpcinfo -p | grep yp | grep udp", shell=True) == 0
        return (not has_pkg) or (not using_udp)
    
    def fix(self):
        remove_package("nis")
        return self.error("Disable and remove NIS or configure the system to not use UDP")

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
        disallow_empty_pw = grep_file(self.fn, "^PermitEmptyPasswords no$")
        return disallow_empty_pw

    def fix(self):        
        replace_line(self.fn, "^PermitEmptyPasswords.*", "PermitEmptyPasswords no")

class v50454(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50454) snmpd must not use default password")
        self.filename = "/etc/snmp/snmp.conf"
        
    def check(self):
        no_public = not grep_file(self.filename, "public")
        return no_public

    def fix(self):
        return self.error("Disable the default public password")


class v50467(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50467) System must use and update a DoD-approved virus scan program")
        self.envvar = "PATH_TO_AV_ZIP"
        self.tarball = "McAfeeVSEForLinux-2.0.0.28948/McAfeeVSEForLinux-2.0.0.28948-release-full.x86_64.tar.gz"
        self.program_name = "nails"
        self.install_prefix = "/opt/NAI/LinuxShield"
        self.cron = ["/etc/cron*", "/var/spool/cron/*"]
        self.options = "doc/nails.options"
        self.data_files = [os.path.join(self.install_prefix,"engine","dat","avvclean.dat"),
                           os.path.join(self.install_prefix,"engine","dat","avvnames.dat"),
                           os.path.join(self.install_prefix,"engine","dat","avvscan.dat")]
                                          
    def check(self):
        av_installed = exists(self.install_prefix) \
            and exists(os.path.join(self.install_prefix, "bin", self.program_name))
        cron_configured = False
        for f in self.cron:
            cron_configured = cron_configured or grep_file(f, self.program_name)
        files_uptodate = True
        for f in self.data_files:
            files_uptodate = files_uptodate and (not older_than(f, 7))
        return av_installed and cron_configured and files_uptodate

    def fix(self):        
        # check if the env var is set
        if os.environ.get(self.envvar):
            zipfile = os.environ.get(self.envvar)
            basename = os.path.basename(zipfile)
            basedir = os.path.dirname(zipfile)
            p.call("pushd " + basedir, shell=True) 
            p.call("unzip " + basename, shell=True) 
            p.call("pushd " + "McAfeeVSEForLinux-2.0.0.28948", shell=True)
            p.call("tar xzf McAfeeVSEForLinux-2.0.0.28948-release-full.x86_64.tar.gz", shell=True)
            p.call("tar xzf McAfeeVSEForLinux-2.0.0.28948-others.tar.gz", shell=True)
            p.call("gksudo dpkg -i MFErt.i686.deb", shell=True)
            p.call("gksudo dpkg -i MFEcma.i686.deb", shell=True)
            p.call("tar xzf McAfeeVSEForLinux-2.0.0.28948-release.tar.gz", shell=True)
            p.call("cp {0} ~/".format(self.options), shell=True)
            p.call("gksudo ./McAfeeVSEForLinux-2.0.0.28948-installer", shell=True)
        else:
            return self.error("Install the McAfee AV program, or set {0} environment variable".format(self.envvar))

class v50469(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50469) Disable ctl-alt-del sequence")
        self.basedir = "/etc/init"

    def get_affected_files(self):
        files_str = ex.run("find "+self.basedir+" -type f -exec grep -l 'start on control-alt-delete' {} \;")
        buf = sio.StringIO(files_str)
        files = []
        for f in buf.readlines():
            ff = s.strip(f)
            files.append(os.path.join(self.basedir,ff))
        return files

    def check(self):
        files = self.get_affected_files()
        shutdown_present = False
        for f in files:
            shutdown_present = shutdown_present or grep_file(f, "^exec shutdown.*")
        return not shutdown_present

    def fix(self):
        files = self.get_affected_files()
        for f in files:
            replace_line(f, "^exec shutdown.*", "exec /usr/bin/logger -p security.info \"Ctl-Alt-Delete pressed\"")

class v50502(STIG):
    def __init__(self):
        STIG.__init__(self, "(v50502) Disable TFTP daemon")
        self.pkgs = ["tftpd","tftpd-hpa","atftpd","python-txtftp"]

    def check(self):
        srv_running = service_running("tftp")
        pkg_installed = False
        for p in self.pkgs:
            pkg_installed = pkg_installed or verify_package(p, do_install=False)
        return not srv_running and not pkg_installed

    def fix(self):
        disable_service("tftp")
        for p in self.pkgs:
            remove_package(p)
        
class v1025(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1025) The /etc/security/access.conf file must be owned by root")
    
    def check(self):
         return (get_file_owner("/etc/security/access.conf")=="root")

    def fix(self):
        get_results(sudo("chown root /etc/security/access.conf"))

class v1055(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1055) The /etc/security/access.conf file must have mode 0640 or less permissive")
    
    def check(self):
        st = os.stat("/etc/security/access.conf")
        prm = oct(st.st_mode & 0777)
        return (prm <= oct(0640))

    def fix(self):
        return get_results(sudo("chmod 0640 /etc/security/access.conf"))

class v1027(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1027) The /etc/samba/smb.conf file must be owned by root")
    
    def check(self):
         return (get_file_owner("/etc/samba/smb.conf")=="root")

    def fix(self):
        get_results(sudo("chown root /etc/samba/smb.conf"))

class v1028(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1028) The smb.conf file must have mode 0644 or less permissive")
    
    def check(self):
        st = os.stat("/etc/samba/smb.conf")
        prm = oct(st.st_mode & 0777)
        return (prm <= oct(0644))

    def fix(self):
        return get_results(sudo("chmod 0644 /etc/samba/smb.conf"))

class v1056(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1056) The /etc/samba/smb.conf file must be group-owned by root, bin, or sys")
    
    def check(self):
         return (get_file_group("/etc/samba/smb.conf")=="root" or
 get_file_group("/etc/samba/smb.conf")=="bin" or
 get_file_group("/etc/samba/smb.conf")=="sys")

    def fix(self):
        get_results(sudo("chgrp root /etc/samba/smb.conf"))

class v1029(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1029) The /usr/bin/smbpasswd file must be owned by root")
    
    def check(self):
         return (get_file_owner("/usr/bin/smbpasswd")=="root")

    def fix(self):
        get_results(sudo("chown root /usr/bin/smbpasswd"))

class v1058(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1058) The /usr/bin/smbpasswd file must be group-owned by root")
    
    def check(self):
         return (get_file_group("/usr/bin/smbpasswd")=="root")

    def fix(self):
        get_results(sudo("chgrp root /usr/bin/smbpasswd"))

class v1059(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1059) The /usr/bin/smbpasswd file must have mode 0600 or less permissive")
    
    def check(self):
        st = os.stat("/usr/bin/smbpasswd")
        prm = oct(st.st_mode & 0777)
        return (prm <= oct(0600))

    def fix(self):
        return get_results(sudo("chmod 0600 /usr/bin/smbpasswd"))
