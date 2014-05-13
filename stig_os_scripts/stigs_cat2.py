from ubuntu import *
import stig_functions
import os
import subprocess as p
import StringIO as sio

# apt-get install libpam-cracklib
# modified /etc/pam.d/common-password
class v1046(STIG):
    def __init__(self):
        STIG.__init__(self,"(v1046) Check for root passwords in clear text")
