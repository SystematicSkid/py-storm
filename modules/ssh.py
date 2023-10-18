__author__ = "SystematicSkid & Campinator"

import os
import sys
import re

# SSH Search Class
class SSHPolicyScanner:
    def __init__(self, directory = '/'):
        self.directory = directory
        # combine directory and sshd_config

        self.ssh_config = os.path.join( self.directory, 'etc', 'ssh', 'ssh_config' )
        self.sshd_config = os.path.join( self.directory, 'etc', 'ssh', 'sshd_config' )
        self.sshd_config_lines = self.read_config(self.sshd_config)


    def read_config( self, filepath ):
        with open( filepath, 'r' ) as f:
            return f.read( ).splitlines( )
        
    def audit_permissions( self, filepath, expected_mode ):
        perms = os.stat( filepath )
        if perms.st_uid != 0 or perms.st_gid != 0 or perms.st_mode & 0o077 != expected_mode:
            print( f'Permissions on {filepath} are not set correctly' )
            return False
        return True
    
    def audit_regex( self, lines, regex, error_message ):
        for line in lines:
            if re.match( regex, line ):
                return True
        print( error_message )
        return False

    def get_public_key_files( self ):
        ssh_files = []
        for root, dirs, files in os.walk( os.path.join( self.directory, 'etc', 'ssh' ) ):
            for file in files:
                if file.endswith( '.pub' ):
                    ssh_files.append( os.path.join( root, file ) )
        return ssh_files
    

    def audit_permissions_main( self ):
        return self.audit_permissions( self.ssh_config, 0o600 )

    def audit_public_permissions( self ):
        ssh_files = self.get_public_key_files( )
        return all( self.audit_permissions( file, 0o644 ) for file in ssh_files )

    def audit_ssh_protocol( self ):
        return self.audit_regex( self.sshd_config_lines, r'^Protocol\s+2', 'Protocol is not set to 2' )

    def audit_ssh_log_level( self ):
        return self.audit_regex( self.sshd_config_lines, r'^LogLevel\s+(INFO|VERBOSE)', 'LogLevel is not set to INFO or VERBOSE' )
    
    def audit_x11_forwarding( self ):
        return self.audit_regex( self.sshd_config_lines, r'^X11Forwarding\s+no', 'X11Forwarding is not set to no' )

    def audit_max_auth_tries( self ):
        return self.audit_regex( self.sshd_config_lines, r'^MaxAuthTries\s+[1-4]', 'MaxAuthTries is not set to 4 or less' )
    
    def audit_ignore_rhosts( self ):
        return self.audit_regex( self.sshd_config_lines, r'^IgnoreRhosts\s+yes', 'IgnoreRhosts is not set to yes' )
    
    def audit_host_based_auth( self ):
        return self.audit_regex( self.sshd_config_lines, r'^HostbasedAuthentication\s+no', 'HostbasedAuthentication is not set to no' )
    
    def audit_root_login( self ):
        return self.audit_regex( self.sshd_config_lines, r'^PermitRootLogin\s+no', 'PermitRootLogin is not set to no' )

    def audit_permit_empty_password( self ):
        return self.audit_regex( self.sshd_config_lines, r'^PermitEmptyPasswords\s+no', 'PermitEmptyPasswords is not set to no' )
    
    def audit_permit_user_environment( self ):
        return self.audit_regex( self.sshd_config_lines, r'^PermitUserEnvironment\s+no', 'PermitUserEnvironment is not set to no' )
    
    def audit_ensure_strong_cipher( self ):
        return self.audit_regex( self.sshd_config_lines, r'^Ciphers\s+.*aes.*', 'Ciphers is not set to a strong cipher' )
    
    def audit_strong_mac_algorithm( self ):
        return self.audit_regex( self.sshd_config_lines, r'^MACs\s+.*hmac-sha2-512', 'MACs is not set to hmac-sha2-512' )
    
    def audit_strong_key_exchange_algorithm( self ):
        return self.audit_regex( self.sshd_config_lines, r'^KexAlgorithms\s+.*curve25519-sha256', 'KexAlgorithms is not set to curve25519-sha256' )
    
    def audit_idle_timeout( self ):
        return self.audit_regex( self.sshd_config_lines, r'^ClientAliveInterval\s+300', 'ClientAliveInterval is not set to 300' )
    
    def audit_client_alive_count_max( self ):
        return self.audit_regex( self.sshd_config_lines, r'^ClientAliveCountMax\s+0', 'ClientAliveCountMax is not set to 0' )
    
    def audit_login_grace( self ):
        return self.audit_regex( self.sshd_config_lines, r'^LoginGraceTime\s+60', 'LoginGraceTime is not set to 60' )
    
    def audit_allowusers( self ):
        return self.audit_regex( self.sshd_config_lines, r'^AllowUsers\s+<username>', 'AllowUsers is not set to <username>' )
    
    def audit_allow_groups( self ):
        return self.audit_regex( self.sshd_config_lines, r'^AllowGroups\s+<groupname>', 'AllowGroups is not set to <groupname>' )
    
    def audit_deny_users( self ):
        return self.audit_regex( self.sshd_config_lines, r'^DenyUsers\s+<username>', 'DenyUsers is not set to <username>' )
    
    def audit_deny_groups( self ):
        return self.audit_regex( self.sshd_config_lines, r'^DenyGroups\s+<groupname>', 'DenyGroups is not set to <groupname>' )
    
    def audit_warning_banner( self ):
        return self.audit_regex( self.sshd_config_lines, r'^Banner\s+/etc/issue.net', 'Banner is not set to /etc/issue.net' )
    
    def audit_pam( self ):
        return self.audit_regex( self.sshd_config_lines, r'^UsePAM\s+yes', 'UsePAM is not set to yes' )
    
    def audit_tcp_forwarding( self ):
        return self.audit_regex( self.sshd_config_lines, r'^AllowTcpForwarding\s+no', 'AllowTcpForwarding is not set to no' )
    
    def audit_max_startups( self ):
        return self.audit_regex( self.sshd_config_lines, r'^MaxStartups\s+10:30:60', 'MaxStartups is not set to 10:30:60' )
    
    def audit_max_sessions( self ):
        return self.audit_regex( self.sshd_config_lines, r'^MaxSessions\s+4', 'MaxSessions is not set to 4' )
    
    def audit_all( self ):
        print('\n=== SSH Policy Settings ===\n')
        # if not self.audit_permissions( ):
            # print('audit_permissions failed')
        if not self.audit_public_permissions( ):
            print('audit_public_permissions failed')
        if not self.audit_ssh_protocol( ):
            print('audit_ssh_protocol failed')
        if not self.audit_ssh_log_level( ):
            print('audit_ssh_log_level failed')
        if not self.audit_x11_forwarding( ):
            print('audit_x11_forwarding failed')
        if not self.audit_max_auth_tries( ):
            print('audit_max_auth_tries failed')
        if not self.audit_ignore_rhosts( ):
            print('audit_ignore_rhosts failed')
        if not self.audit_host_based_auth( ):
            print('audit_host_based_auth failed')
        if not self.audit_root_login( ):
            print('audit_root_login failed')
        if not self.audit_permit_empty_password( ):
            print('audit_permit_empty_password failed')
        if not self.audit_permit_user_environment( ):
            print('audit_permit_user_environment failed')
        if not self.audit_ensure_strong_cipher( ):
            print('audit_ensure_strong_cipher failed')
        if not self.audit_strong_mac_algorithm( ):
            print('audit_strong_mac_algorithm failed')
        if not self.audit_strong_key_exchange_algorithm( ):
            print('audit_strong_key_exchange_algorithm failed')
        if not self.audit_idle_timeout( ):
            print('audit_idle_timeout failed')
        if not self.audit_client_alive_count_max( ):
            print('audit_client_alive_count_max failed')
        if not self.audit_login_grace( ):
            print('audit_login_grace failed')
        if not self.audit_allowusers( ):
            print('audit_allowusers failed')
        if not self.audit_allow_groups( ):
            print('audit_allow_groups failed')
        if not self.audit_deny_users( ):
            print('audit_deny_users failed')
        if not self.audit_deny_groups( ):
            print('audit_deny_groups failed')
        if not self.audit_warning_banner( ):
            print('audit_warning_banner failed')
        if not self.audit_pam( ):
            print('audit_pam failed')
        if not self.audit_tcp_forwarding( ):
            print('audit_tcp_forwarding failed')
        if not self.audit_max_startups( ):
            print('audit_max_startups failed')
        if not self.audit_max_sessions( ):
            print('audit_max_sessions failed')
        return True
