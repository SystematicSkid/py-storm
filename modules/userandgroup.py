""" User and Group Policy Scanner, based on CIS Benchmarks """
__author__ = "Campinator"


import os
import re

class UserGroupPolicyScanner:
   def __init__(self, directory = "/"):
      self.directory = directory
      self.etc_dir = os.path.join(directory, 'etc')
      self.shadow = os.path.join( self.etc_dir, 'shadow' )
      self.passwd = os.path.join( self.etc_dir, 'passwd' )
      self.group = os.path.join( self.etc_dir, 'group' )

      self.shadow_lines = self.read_config(self.shadow)
      # print(f"SHADOW:\n\n{self.shadow_lines}\n\n")
      self.passwd_lines = self.read_config(self.passwd)
      # print(f"PASSWD:\n\n{self.passwd_lines}\n\n")
      self.group_lines = self.read_config(self.group)
      # print(f"GROUP:\n\n{self.group_lines}\n\n")

   # helper functions

   def read_config( self, filepath ):
        with open( filepath, 'r' ) as f:
            return f.read( ).splitlines( )
        
   def audit_permissions( self, filepath, expected_mode ):
        perms = os.stat( filepath )
        if perms.st_uid != 0 or perms.st_gid != 0 or perms.st_mode & 0o077 != expected_mode:
            print( f'Permissions on {filepath} are not set correctly (6.1.1)' )
            return False
        return True
    
   def audit_regex( self, lines, regex, error_message ):
      for line in lines:
         if re.match( regex, line ):
               return True
      print( error_message )
      return False
   
   def path_exists( self, dirpath ):
      return os.path.exists( dirpath )
   
   # 6.2.1 password fields not empty
   def audit_empty_password_fields( self ):
      for line in self.shadow_lines:
         if line.split(":")[1] == "":
            print( f"Account {line.split(':')[0]} has an empty password field (6.2.1)" )
            return False
      return True

   # 6.2.2 no + entries in passwd
   def audit_legacy_plus_entries_passwd( self ):
      for line in self.passwd_lines:
         if "+" in line:
            print(f"Legacy '+' entry in /etc/passwd: {line.split(':')[0]} (6.2.2)")
            return False
      return True

   # 6.2.3 users home directories exist
   def audit_home_directories_and_a_bunch_else( self ):
      passed = True
      for line in self.passwd_lines:
         parts = line.split(":")
         if parts[0] in ['halt', 'sync', 'shutdown']: #skip these users
            continue
         if parts[6] == "/bin/false" or parts[6] == "/usr/sbin/nologin" or parts[6] == "/sbin/nologin":
            # no interactive shell access
            continue
         elif not self.path_exists( os.path.join( self.directory, parts[5][1:] ) ):
            print(f"Home directory for ${parts[0]} does not exist (6.2.3)")
            passed = False
         
         # 6.2.11 no .forward files
         if self.path_exists( os.path.join( self.directory, parts[5][1:], ".forward" ) ):
            print(f".forward file exists for ${parts[0]} account (6.2.11)")
            passed = False
         
         # 6.2.12 no .netrc files
         if self.path_exists( os.path.join( self.directory, parts[5][1:], ".netrc" ) ):
            print(f".netrc file exists for ${parts[0]} account (6.2.12)")
            passed = False

         # 6.2.14 no .rhosts files
         if self.path_exists( os.path.join( self.directory, parts[5][1:], ".rhosts" ) ):
            print(f".rhosts file exists for ${parts[0]} account (6.2.14)")
            passed = False
      return passed


   # 6.2.4 no + entries in shadow
   def audit_legacy_plus_entries_shadow( self ):
      for line in self.shadow_lines:
         if "+" in line:
            print(f"Legacy '+' entry in /etc/shadow: {line.split(':')[0]} (6.2.4)")
            return False
      return True

   # 6.2.5 no + entries in group
   def audit_legacy_plus_entries_group( self ):
      for line in self.group_lines:
         if "+" in line:
            print(f"Legacy '+' entry in /etc/group: {line.split(':')[0]} (6.2.5)")
            return False
      return True

   # 6.2.6 root only UID 0
   def audit_uid_zero( self ):
      zero_uids = []
      for line in self.passwd_lines:
         if line.split(':')[2] == "0":
            zero_uids.append(line.split(':')[0])
      if zero_uids != ["root"]:
         print(f"Multiple users have UID of 0: {zero_uids} (6.2.6)")
         return False
      return True
      
   # 6.2.7 PATH integrity
   def audit_path_integrity( self ):
      env = self.read_config( os.path.join(self.directory, "etc", "environment") )
      paths = [e for e in env if e.startswith("PATH")]
      if len(paths) > 1:
         print("ERROR: multiple PATHs set (6.2.7)")
         return False
      path = paths[0]
      if "::" in path:
         print("Empty directory in PATH (::) (6.2.7)")
         return False
      if path.endswith(":"):
         print("Trailing ':' in PATH (6.2.7)")
         return False
      return True

   # 6.2.8 restrictive home directory permissions
   '''TODO'''

   # 6.2.9 user owns home directory
   '''TODO'''

   # 6.2.10 dotfiles not writable
   '''TODO'''

   # 6.2.13 .netrc files not accessible
   '''TODO'''

   # 6.2.15 everyone in passwd in group
   def audit_passwd_and_group_match( self ):
      gids_p = set()
      gids_g = set()

      for line in self.passwd_lines:
         parts = line.split(":")
         gids_p.add(parts[3])
      for line in self.group_lines:
         parts = line.split(":")
         gids_g.add(parts[2])
      
      diff = gids_p.difference(gids_g)
      if len(diff) > 0:
         print(f"Group(s) {diff} referenced by /etc/passwd but not found in /etc/group (6.2.15)")
         return False
      return True      

   # 6.2.16 no duplicate UIDs
   def audit_duplicate_uid( self ):
      uids = []
      for line in self.passwd_lines:
         uids.append(int(line.split(":")[2]))
      counts = [uids.count(id) for id in uids]
      for c in range(len(counts)):
         if counts[c] > 1:
            print(f"Duplicate UID found in /etc/passwd: {uids[c]} (6.2.16)")
            return False
      return True

   # 6.2.17 no duplicate GIDs
   def audit_duplicate_gid( self ):
      gids = []
      for line in self.group_lines:
         gids.append(int(line.split(":")[2]))
      counts = [gids.count(id) for id in gids]
      for c in range(len(counts)):
         if counts[c] > 1:
            print(f"Duplicate UID found in /etc/group: {gids[c]} (6.2.17)")
            return False
      return True

   # 6.2.18 no duplicate usernames
   def audit_duplicate_user_name( self ):
      users = []
      for line in self.passwd_lines:
         users.append(line.split(":")[0])
      counts = [users.count(u) for u in users]
      for c in range(len(counts)):
         if counts[c] > 1:
            print(f"Duplicate user found: {users[c]} (6.2.18)")
            return False
      return True

   # 6.2.19 no duplicate group names
   def audit_duplicate_group_name( self ):
      groups = []
      for line in self.passwd_lines:
         groups.append(line.split(":")[0])
      counts = [groups.count(g) for g in groups]
      for c in range(len(counts)):
         if counts[c] > 1:
            print(f"Duplicate group found: {groups[c]} (6.2.19)")
            return False
      return True

   # 6.2.20 shadow group empty
   def audit_shadow_group_empty( self ):
      for line in self.group_lines:
         parts = line.split(":")
         if parts[0] == "shadow":
            if parts[3] != '':
               print(f"Shadow group is not empty: {parts[3]} (6.2.20)")
               return False
      return True
   
   # Not from CIS Benchmarks but checked in past HiveStorm events
   def list_users_in_sudo_group( self ):
      sudo_groups = [line for line in self.group_lines if line.startswith("sudo")]
      if len(sudo_groups) > 1:
         print("Multiple sudo groups, probably bad\n")
      sudo_group = sudo_groups[0].split(":")
      print(f"Sudo group: {sudo_group[3]}\n")

   def list_users_with_passwords( self ):
      users = []
      for line in self.shadow_lines:
         if line.split(":")[1] != '':
            users.append(line.split(":")[0])
      print(f"Users with passwords set: {', '.join(users)}\n")


   def audit_all( self ):
      print('\n=== User and Group Settings ===\n')
      if not self.audit_empty_password_fields():
         print('audit_empty_password_fields failed\n')
      if not self.audit_home_directories_and_a_bunch_else():
         print('audit_home_directories_and_a_bunch_else failed\n')
      if not self.audit_legacy_plus_entries_group():
         print('audit_legacy_plus_entries_group failed\n')
      if not self.audit_legacy_plus_entries_passwd():
         print('audit_legacy_plus_entries_passwd failed\n')
      if not self.audit_legacy_plus_entries_shadow():
         print('audit_legacy_plus_entries_shadow failed\n')
      if not self.audit_uid_zero():
         print('audit_uid_zero failed\n')
      if not self.audit_path_integrity():
         print('audit_path_integrity failed\n')
      if not self.audit_passwd_and_group_match():
         print('audit_passwd_and_group_match failed\n')
      if not self.audit_duplicate_uid():
         print('audit_duplicate_uid failed\n')
      if not self.audit_duplicate_gid():
         print('audit_duplicate_gid failed\n')
      if not self.audit_duplicate_user_name():
         print('audit_duplicate_user_name failed\n')
      if not self.audit_duplicate_group_name():
         print('audit_duplicate_group_name failed\n')
      if not self.audit_shadow_group_empty():
         print('audit_shadow_group_empty failed\n')
      
      self.list_users_in_sudo_group()
      self.list_users_with_passwords()
      return True