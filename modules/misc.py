__author__ = "SystematicSkid"

import os
import sys
import re

# SSH Search Class
class SysCtlPolicyScanner:
    def __init__(self, directory = '/'):
        self.directory = directory


    def read_config( self, filepath ):
        with open( filepath, 'r' ) as f:
            return f.read( ).splitlines( )
    
    def check_audit_regex( self, lines, regex, error_message ):
        for line in lines:
            if re.match( regex, line ):
                return True
        print( error_message )
        return False
    
    def audit_shared_mem_ro( self ):
        # Read /etc/fstab
        fstab = os.path.join( self.directory, 'etc', 'fstab' )
        fstab_lines = self.read_config( fstab )
        # Ensure shm tmpfs is mounted with noexec
        for line in fstab_lines:
            if re.match( r'(?i)shm\s+tmpfs\s+\S*noexec', line ):
                return True
            
    def audit_lightdm_guest( self ):
        # Check if lightdm is installed
        lightdm = os.path.join( self.directory, 'etc', 'lightdm', 'lightdm.conf' )
        if os.path.exists( lightdm ):
            lightdm_lines = self.read_config( lightdm )
            # Ensure guest account is disabled and SeatDefaults is set
            is_good = True
            for line in lightdm_lines:
                if not re.match( r'(?i)^\s*allow-guest\s*=\s*false', line ):
                    is_good = False
                if not re.match( r'(?i)^\s*\[Seat(Defaults|:\*)\]', line ):
                    is_good = False
            if is_good:
                return True
            else:
                print( "lightdm is not configured correctly" )
                return False
            
    def audit_sources_list( self ):
        # Check if we have a sources.list
        sources_list = os.path.join( self.directory, 'etc', 'apt', 'sources.list' )
        if not os.path.exists( sources_list ):
            print( "No sources.list found" )
            return False
        sources_list_lines = self.read_config( sources_list )
        security_regex = r"^\s*deb\s+http://security.ubuntu.com/ubuntu/\s+"
        # Ensure we have security.ubuntu.com in our sources.list
        for line in sources_list_lines:
            if re.match( security_regex, line ):
                return True
        print( "No security.ubuntu.com found in sources.list" )

    def audit_mysql_bind( self ):
        # Check if mysql is installed
        mysql = os.path.join( self.directory, 'etc', 'mysql' )
        # If it doesn't exist, we're good
        if not os.path.exists( mysql ):
            return True
        # If it does, check if it's configured correctly
        mysql_cnf = os.path.join( mysql, 'my.cnf' )
        if not os.path.exists( mysql_cnf ):
            print( "MySQL is installed but not configured correctly" )
            return False
        mysql_cnf_lines = self.read_config( mysql_cnf )
        # Ensure we have bind-address = localhost
        found_bind_address = False
        found_skip_networking = False
        for line in mysql_cnf_lines:
            # Check if bind address is localhost or 127.0.0.1
            if re.match( r"^\s*bind-address\s*=\s*127\.0\.0\.1", line ) or re.match( r"^\s*bind-address\s*=\s*localhost", line ):
                found_bind_address = True
            # Check 'skip-networking' is set
            if not re.match( r"^\s*skip-networking", line ):
                found_skip_networking = True
        if found_bind_address and found_skip_networking:
            return True
        else:
            print( "MySQL is not configured correctly" )
            return False
        
    def audit_php5( self ):
        # Check if php5 is installed
        php5 = os.path.join( self.directory, 'etc', 'php5' )
        # If it doesn't exist, we're good
        if not os.path.exists( php5 ):
            return True
        # If it does, check if it's configured correctly
        php5_ini = os.path.join( php5, 'apache2', 'php.ini' )
        if not os.path.exists( php5_ini ):
            print( "php5 is installed but not configured correctly" )
            return False
        php5_ini_lines = self.read_config( php5_ini )
        # Ensure expose_php is set to off
        expose_php_off = False
        error_reporting = False
        display_errors_off = False
        display_startup_errors_off = False
        log_errors_on = False
        ignore_repeat_errors_off = False

        for line in php5_ini_lines:
            # Check if expose_php is off
            if re.match( r"^\s*expose_php\s*=\s*Off", line ):
                expose_php_off = True
            # Check if error_reporting is set
            if re.match( r"^\s*error_reporting\s*=\s*E_ALL", line ):
                error_reporting = True
            # Check if display_errors is off
            if re.match( r"^\s*display_errors\s*=\s*Off", line ):
                display_errors_off = True
            # Check if display_startup_errors is off
            if re.match( r"^\s*display_startup_errors\s*=\s*Off", line ):
                display_startup_errors_off = True
            # Check if log_errors is on
            if re.match( r"^\s*log_errors\s*=\s*On", line ):
                log_errors_on = True
            # Check if ignore_repeated_errors is off
            if re.match( r"^\s*ignore_repeated_errors\s*=\s*Off", line ):
                ignore_repeat_errors_off = True

        if expose_php_off and error_reporting and display_errors_off and display_startup_errors_off and log_errors_on and ignore_repeat_errors_off:
            return True
        else:
            print( "php5 is not configured correctly" )
            return False
        