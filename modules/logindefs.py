__author__ = "SystematicSkid"

import os
import sys
import re

# login.defs Search Class
class LoginDefsPolicyScanner:
    def __init__(self, directory = '/'):
        self.directory = directory
        # combine directory and sshd_config

        self.logindefs = os.path.join( self.directory, 'etc', 'login.defs' )
        self.logindef_lines = self.read_config(self.logindefs)


    def read_config( self, filepath ):
        with open( filepath, 'r' ) as f:
            return f.read( ).splitlines( )
    
    def check_audit_regex( self, lines, regex, error_message ):
        for line in lines:
            if re.match( regex, line ):
                return True
        print( error_message )
        return False
    
    def audit_faillog_enab( self ):
        return self.check_audit_regex( self.logindef_lines, r'^FAILLOG_ENAB\s+yes', 'FAILLOG_ENAB is not set to yes' )

    def audit_fillog_unk_enab( self ):
        return self.check_audit_regex( self.logindef_lines, r'^LOG_UNKFAIL_ENAB\s+yes', 'LOG_UNKFAIL_ENAB is not set to yes' )
    
    def audit_log_ok_logins( self ):
        return self.check_audit_regex( self.logindef_lines, r'^LOG_OK_LOGINS\s+no', 'LOG_OK_LOGINS is not set to no' )
    
    def audit_syslog_su_enab( self ):
        return self.check_audit_regex( self.logindef_lines, r'^SYSLOG_SU_ENAB\s+yes', 'SYSLOG_SU_ENAB is not set to yes' )
    
    def audit_syslog_sg_enab( self ):
        return self.check_audit_regex( self.logindef_lines, r'^SYSLOG_SG_ENAB\s+yes', 'SYSLOG_SG_ENAB is not set to yes' )
    
    def audit_pass_max_days( self ):
        return self.check_audit_regex( self.logindef_lines, r'^PASS_MAX_DAYS\s+90', 'PASS_MAX_DAYS is not set to 90' )
    
    def audit_pass_min_days( self ):
        return self.check_audit_regex( self.logindef_lines, r'^PASS_MIN_DAYS\s+7', 'PASS_MIN_DAYS is not set to 7' )
    
    def audit_pass_warn_age( self ):
        return self.check_audit_regex( self.logindef_lines, r'^PASS_WARN_AGE\s+7', 'PASS_WARN_AGE is not set to 7' )

    def audit_login_retries( self ):
        return self.check_audit_regex( self.logindef_lines, r'^LOGIN_RETRIES\s+3', 'LOGIN_RETRIES is not set to 3' )
    
    def audit_login_timeout( self ):
        return self.check_audit_regex( self.logindef_lines, r'^LOGIN_TIMEOUT\s+60', 'LOGIN_TIMEOUT is not set to 60' )
    
    def audit_encrypt_method( self ):
        return self.check_audit_regex( self.logindef_lines, r'^ENCRYPT_METHOD\s+yescrypt', 'ENCRYPT_METHOD is not set to yescrypt' )
    
    def audit_all( self ):
        print("\n=== Logindefs ===\n")
        return all( getattr( self, f )() for f in dir( self ) if re.match( r'^audit_', f ) )