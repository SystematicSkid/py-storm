__author__ = "Campinator & SystematicSkid"

import os
import sys
import re

class PAMPolicyScanner:
    def __init__(self, directory = "/"):
        self.security_folder = os.path.join( directory, "etc", "security" )
        self.pam_folder = os.path.join( directory, "pam.d" )

    def audit_password_requirements( self ):
        # Check /etc/security/pwquality.conf
        pwquality_conf = os.path.join( self.security_folder, "pwquality.conf" )
        if os.path.exists( pwquality_conf ):
            # Check for minlen
            minlen = 0
            with open( pwquality_conf, "r" ) as f:
                for line in f:
                    if re.match( r"^minlen", line ):
                        minlen = int( line.split()[1] )
                        break
            if minlen < 14:
                print( "Password length is less than 14 characters" )
            else:
                print( "Password length is greater than 14 characters" )
            # Check minclass
            minclass = 0
            with open( pwquality_conf, "r" ) as f:
                # Check for minclass
                for line in f:
                    if re.match( r"^\s*minclass\s*", line ):
                        minclass = int( line.split()[1] )
                        break
            if minclass < 4:
                print( "Password does not contain at least 4 character classes" )
            else:
                print( "Password contains at least 4 character classes" )

        # Check /etc/pam.d/common-password
        common_password = os.path.join( self.pam_folder, "common-password" )
        if os.path.exists( common_password ):
            # Open file
            with open( common_password, "r" ) as f:
                for line in f:
                    if re.match( r"^\s*password\s+(requisite|required)\s+pam_pwquality\.so\s+(\S+\s+)*retry=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$" ):
                        print( "Password policy is set correctly" )
                    else:
                        print( "Password policy is not set correctly" )

        return True
    
    def audit_lockout_policy( self ):
        # Check /etc/pam.d/common-auth
        common_auth = os.path.join( self.pam_folder, "common-auth" )
        if os.path.exists( common_auth ):
            # Open file
            with open( common_auth, "r" ) as f:
                for line in f:
                    if re.match( r"^\s*auth\s+(required|requisite)\s+pam_tally2\.so\s+(\S+\s+)*deny=[1-3]\s*(\s+\S+\s*)*(\s+#.*)?$" ):
                        print( "Lockout policy is set correctly" )
                    else:
                        print( "Lockout policy is not set correctly" )
                        return False
        return True
    
    def audit_failed_attempts( self ):
        # Check /etc/pam.d/common-auth
        common_auth = os.path.join( self.pam_folder, "common-auth" )
        if os.path.exists( common_auth ):
            # Open file
            with open( common_auth, "r" ) as f:
                for line in f:
                    if re.match( r"pam_tally2" ):
                        # Check for deny=5
                        if re.match( r"deny=5" ):
                            print( "Lockout policy is set correctly" )
                            return True
        return False
    
    def audit_password_reuse( self ):
        # Check /etc/pam.d/common-password
        grep_re = r"'^password\s+required\s+pam_pwhistory.so"
        common_password = os.path.join( self.pam_folder, "common-password" )
        if os.path.exists( common_password ):
            # Open file
            with open( common_password, "r" ) as f:
                for line in f:
                    if re.match( grep_re, line ):
                        # Check for remember=5
                        if re.match( r"remember=5", line ):
                            print( "Password reuse policy is set correctly" )
                            return True
        return False
    
    def audit_pwhistory_enabled( self ):
        re_check = r"(?i)^\s*password[^\n]*pam_pwhistory.so"
        common_password = os.path.join( self.pam_folder, "common-password" )
        if os.path.exists( common_password ):
            # Open file
            with open( common_password, "r" ) as f:
                for line in f:
                    if re.match( re_check, line ):
                        print( "Password history is enabled" )
                        return True
                    
        return False
    
    def audit_all( self ):
        print('\n=== PAM Policy Settings ===\n')
        if not self.audit_password_requirements():
            print('sudit_password_requirements failed\n')
        if not self.audit_lockout_policy():
            print('sudit_lockout_policy failed\n')
        if not self.audit_failed_attempts():
            print('sudit_failed_attempts failed\n')
        if not self.audit_password_reuse():
            print('sudit_password_reuse failed\n')
        return True