""" PyStorm Hivestorm Script """
__author__ = 'SystematicSkid, Campinator, and AlecHoward76'


from modules.ssh import SSHPolicyScanner
from modules.userandgroup import UserGroupPolicyScanner
from modules.net import NetworkConfigScanner
from modules.pam import PAMPolicyScanner


if __name__ == '__main__':
    # Define our entrypoint, always '/'
    entrypoint = '/'

    # Show stylized header
    print( '----------------------------------------' )
    print( 'PyStorm v1.0 - Python Security Auditing' )
    print( 'University of Tulsa - 2023' )
    print( '----------------------------------------' )
    print( '' )

    # Run ssh scan
    ssh_policy = SSHPolicyScanner( entrypoint )
    ssh_policy.audit_all( )

    pam_policy = PAMPolicyScanner( entrypoint )

    # Run user and group fan
    usergroup_policy = UserGroupPolicyScanner( entrypoint )
    usergroup_policy.audit_all( )

    # Run network scan
    network_policy = NetworkConfigScanner ( entrypoint )
    network_policy.audit_all( )

