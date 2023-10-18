__author__ = "AlecHoward76"

import os
import sys
import re


class NetworkConfigScanner:
    """Class to scan the network configuration of a dead filesystem"""

    # create __init__ method
    def __init__(self, directory = "/"):
        self.directory = directory
        self.etc_dir = os.path.join(directory, "etc")
        self.shadow = os.path.join(self.etc_dir, "shadow")
        self.passwd = os.path.join(self.etc_dir, "passwd")
        self.group = os.path.join(self.etc_dir, "group")

        self.shadow_lines = self.read_config(self.shadow)
        self.passwd_lines = self.read_config(self.passwd)
        self.group_lines = self.read_config(self.group)

    def read_config(self, filepath):
        """Read Config file read"""
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read().splitlines()

    def audit_ufw_enabled(self):
        """Check if the ufw firewall in a dead filesystem is enabled"""

        pattern = r"ENABLED=yes"
        with open(
            os.path.join(self.directory, "etc", "ufw", "ufw.conf"),
            "r",
            encoding="utf-8",
        ) as file:
            lines = file.readlines()
            for line in lines:
                if re.match(pattern, line):
                    return True
            return False

    def audit_default_deny(self):
        """Check if the ufw firewall in a dead filesystem is set to default deny"""

        with open(
            os.path.join(self.directory, "etc", "default", "ufw"), "r", encoding="utf-8"
        ) as file:
            lines = file.readlines()
            counter = 0
            for line in lines:
                if 'DEFAULT_INPUT_POLICY="DROP"' in line:
                    counter += 1
                if 'DEFAULT_OUTPUT_POLICY="DROP"' in line:
                    counter += 1
                if 'DEFAULT_FORWARD_POLICY="DROP"' in line:
                    counter += 1
            if counter == 3:
                return True
            else:
                return False

    def audit_all(self):
        """Run all audit checks"""
        print("\n=== Network Configuration ===\n")
        if not self.audit_ufw_enabled():
            print("Ufw firewall is not enabled (3.5.2.1)")
        """
        if not self.audit_default_deny():
            print("Ufw firewall is not set to default deny (3.5.2.2)")
        """

        return True

    """
    MAIN Call
    # Run network scan
    network_policy = NetworkConfigScanner ( args.directory )
    network_policy.audit_all( )
    """
