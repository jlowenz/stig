from ubuntu import *
import stig_functions
import os
import subprocess as p
import StringIO as sio
from stigs_cat1 import STIG

# apt-get install libpam-cracklib
# modified /etc/pam.d/common-password
class v1046(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1046) Check for root passwords in clear text")

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



