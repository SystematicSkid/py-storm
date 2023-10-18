__author__ = "SystematicSkid"

import os
import re

# SSH Search Class
class SysCtlPolicyScanner:
    def __init__(self, directory = '/'):
        self.directory = directory
        # combine directory and sshd_config

        self.sysctl = os.path.join( self.directory, 'etc', 'sysctl.conf' )
        self.sysctl_lines = self.read_config(self.sysctl)


    def read_config( self, filepath ):
        with open( filepath, 'r' ) as f:
            return f.read( ).splitlines( )
    
    def check_audit_regex( self, lines, regex, error_message ):
        for line in lines:
            if re.match( regex, line ):
                return True
        print( error_message )
        return False
    
    # Audit tcp_synack_retries, ensure less 3
    def audit_tcp_synack_retries( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_synack_retries\s+[1-2]', 'net.ipv4.tcp_synack_retries is not set to 2 or less' )
    # Audit tcp_rfc1337, ensure enabled
    def audit_tcp_rfc1337( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_rfc1337\s+1', 'net.ipv4.tcp_rfc1337 is not set to 1' )
    # Audit tcp_fin_timeout, ensure less than or equal to 15
    def audit_tcp_fin_timeout( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_fin_timeout\s+[1-9]|1[0-5]', 'net.ipv4.tcp_fin_timeout is not set to 15 or less' )
    # Audit tcp_keepalive_time, ensure less than or equal to 300
    def audit_tcp_keepalive_time( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_keepalive_time\s+[1-2][0-9][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9]', 'net.ipv4.tcp_keepalive_time is not set to 300 or less' )
    # Audit tcp_keepalive_intvl, ensure is 15
    def audit_tcp_keepalive_intvl( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_keepalive_intvl\s+15', 'net.ipv4.tcp_keepalive_intvl is not set to 15' )
    # Audit tcp_keepalive_probes, ensure is 5
    def audit_tcp_keepalive_probes( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_keepalive_probes\s+5', 'net.ipv4.tcp_keepalive_probes is not set to 5' )
    # Audit sysrq, ensure is 0
    def audit_sysrq( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^kernel.sysrq\s+0', 'kernel.sysrq is not set to 0' )
    # Audit tcp_syncookies, ensure is 1
    def audit_tcp_syncookies( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.tcp_syncookies\s+1', 'net.ipv4.tcp_syncookies is not set to 1' )
    # Audit ip_forward, ensure is 0
    def audit_ip_forward( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.ip_forward\s+0', 'net.ipv4.ip_forward is not set to 0' )
    # Audit send_redirects, ensure is 0 for all and default
    def audit_send_redirects( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.all.send_redirects\s+0', 'net.ipv4.conf.all.send_redirects is not set to 0' ) and self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.default.send_redirects\s+0', 'net.ipv4.conf.default.send_redirects is not set to 0' )
    # Audit accept_source_route, ensure is 0 for all and default
    def audit_accept_source_route( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.(all|default).accept_source_route\s+0', 'net.ipv4.conf.(all|default).accept_source_route is not set to 0' )
    # Audit accept_redirects, ensure is 0 for all and default
    def audit_accept_redirects( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.(all|default).accept_redirects\s+0', 'net.ipv4.conf.(all|default).accept_redirects is not set to 0' )

    # Audit secure_redirects, ensure is 0 for all and default
    def audit_secure_redirects( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.(all|default).secure_redirects\s+0', 'net.ipv4.conf.(all|default).secure_redirects is not set to 0' )

    # Audit log_martians, ensure is 1 for all and default
    def audit_log_martians( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.(all|default).log_martians\s+1', 'net.ipv4.conf.(all|default).log_martians is not set to 1' )
    
    # Audit icmp_echo_ignore_broadcasts, ensure is 1
    def audit_icmp_echo_ignore_broadcasts( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.icmp_echo_ignore_broadcasts\s+1', 'net.ipv4.icmp_echo_ignore_broadcasts is not set to 1' )
    
    # Audit icmp_ignore_bogus_error_responses, ensure is 1
    def audit_icmp_ignore_bogus_error_responses( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.icmp_ignore_bogus_error_responses\s+1', 'net.ipv4.icmp_ignore_bogus_error_responses is not set to 1' )
    
    # Audit rp_filter, ensure is 1 for all and default
    def audit_rp_filter( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv4.conf.(all|default).rp_filter\s+1', 'net.ipv4.conf.(all|default).rp_filter is not set to 1' )

    # Audit accept_ra, ensure is 0 for all and default
    def audit_accept_ra( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv6.conf.(all|default).accept_ra\s+0', 'net.ipv6.conf.(all|default).accept_ra is not set to 0' )

    # Audit accept_redirects, ensure is 0 for all and default
    def audit_accept_redirects2( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^net.ipv6.conf.(all|default).accept_redirects\s+0', 'net.ipv6.conf.(all|default).accept_redirects is not set to 0' )

    # Audit kptr_restrict, ensure is 2
    def audit_kptr_restrict( self ):
        return self.check_audit_regex( self.sysctl_lines, r'^kernel.kptr_restrict\s+2', 'kernel.kptr_restrict is not set to 2' )

    def audit_all( self ):
        print("\n=== Sysctl Policies ===\n")
        return all( getattr( self, f )() for f in dir( self ) if re.match( r'^audit_', f ) )