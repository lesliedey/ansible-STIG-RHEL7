echo "STIG R2 28 July 2017"

echo "___________________________________________________________________________________________________________________"
echo "Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.
Check the file permissions, ownership, and group membership of system files and commands with the following command:

# rpm -Va | grep '^.M'

If there is any output from the command indicating that the ownership or group of a system file or command, or a system
file, has permissions less restrictive than the default, this is a finding."
if [ "$(rpm -Va | grep '^.M')" == "" ]; then
  echo "not a finding"
else
  echo "required manual check"
  rpm -Va | grep '^.M'
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the cryptographic hash of system files and commands match the vendor values.
Check the cryptographic hash of system files and commands with the following command:
Note: System configuration files (indicated by a 'c' in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.

# rpm -Va | grep '^..5'

If there is any output from the command for system binaries, this is a finding."
if [ "$(rpm -Va | grep '^..5')" == "" ]; then
  echo "not a finding"
else
  echo "required manual check"
  rpm -Va | grep '^..5'
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check to see if the operating system displays a banner at the logon screen with the following command:

# grep banner-message-enable /etc/dconf/db/local.d/*

banner-message-enable=true
If 'banner-message-enable' is set to 'false' or is missing, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^banner-message-enable /etc/dconf/db/local.d/*)" == "banner-message-enable=true" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i banner-message-enable /etc/dconf/db/local.d/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system displays the approved Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check that the operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text with the command:

# grep banner-message-text /etc/dconf/db/local.d/*

banner-message-text=
‘You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to,
penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring
of the content of privileged communications, or work product, related to personal representation or services by attorneys,
psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.’
If the banner does not match the approved Standard Mandatory DoD Notice and Consent Banner, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i banner-message-text /etc/dconf/db/local.d/*)" == "banner-message-text=" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i banner-message-text /etc/dconf/db/local.d/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon.
Check to see if the operating system displays a banner at the command line logon screen with the following command:

# more /etc/issue

The command should return the following text:
'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
If the text in the '/etc/issue' file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
cat /etc/issue

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures. The screen program must be installed to lock sessions on the console.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check to see if the screen lock is enabled with the following command:

# grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver

lock-enabled=true
If the 'lock-enabled' setting is missing or is not set to 'true', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^lock-enabled /etc/dconf/db/local.d/00-screensaver)" == "lock-enabled=true" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check to see if GNOME is configured to display a screensaver after a 15 minute delay with the following command:

# grep -i idle-delay /etc/dconf/db/local.d/*

idle-delay=uint32 900
If the 'idle-delay' setting is missing or is not set to '900' or less, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^idle-delay /etc/dconf/db/local.d/*)" == "idle-delay=uint32 900" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i idle-delay /etc/dconf/db/local.d/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prevents a user from overriding session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Determine which profile the system database is using with the following command:

#grep system-db /etc/dconf/profile/user

system-db:local
Check for the lock delay setting with the following command:
Note: The example below is using the database 'local' for the system, so the path is '/etc/dconf/db/local.d'. This path must be modified if a database other than 'local' is being used.

# grep -i idle-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/idle-delay
If the command does not return a result, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep system-db /etc/dconf/profile/user

if [ "$(grep -i ^idle-delay /etc/dconf/db/local.d/locks/*)" == "/org/gnome/desktop/screensaver/idle-delay" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i idle-delay /etc/dconf/db/local.d/locks/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system has the screen package installed.
Check to see if the screen package is installed with the following command:

# yum list installed | grep screen

screen-4.3.1-3-x86_64.rpm
If is not installed, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(yum list installed screen | grep -i screen)" != "" ]; then
  echo "not a finding"
else
  echo "required manual check"
  yum list installed screen
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.
If it is installed, GNOME must be configured to enforce a session lock after a 15-minute delay. Check for the session lock settings with the following commands:

# grep -i idle_activation_enabled /etc/dconf/db/local.d/*

[org/gnome/desktop/screensaver] idle-activation-enabled=true
If 'idle-activation-enabled' is not set to 'true', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^idle_activation_enabled /etc/dconf/db/local.d/*)" == "idle-activation-enabled=true" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i idle_activation_enabled /etc/dconf/db/local.d/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated. The screen program must be installed to lock sessions on the console.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
If GNOME is installed, check to see a session lock occurs when the screensaver is activated with the following command:

# grep -i lock-delay /etc/dconf/db/local.d/*

lock-delay=uint32 5
If the 'lock-delay' setting is missing, or is not set, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^lock-delay /etc/dconf/db/local.d/*)" == "lock-delay=uint32 5" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i lock-delay /etc/dconf/db/local.d/*
fi

echo "___________________________________________________________________________________________________________________"
echo "Note: The value to require a number of upper-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'.
Check the value for 'ucredit' in '/etc/security/pwquality.conf' with the following command:

# grep ucredit /etc/security/pwquality.conf

ucredit = -1
If the value of 'ucredit' is not set to a negative value, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^ucredit /etc/security/pwquality.conf)" == "ucredit = -1" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i ucredit /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "Note: The value to require a number of lower-case characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'.
Check the value for 'lcredit' in '/etc/security/pwquality.conf' with the following command:

# grep lcredit /etc/security/pwquality.conf

lcredit = -1
If the value of 'lcredit' is not set to a negative value, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^lcredit /etc/security/pwquality.conf)" == "lcredit = -1" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i lcredit /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "Note: The value to require a number of numeric characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'.
Check the value for 'dcredit' in '/etc/security/pwquality.conf' with the following command:

# grep dcredit /etc/security/pwquality.conf

dcredit = -1
If the value of 'dcredit' is not set to a negative value, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^dcredit /etc/security/pwquality.conf)" == "dcredit = -1" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i dcredit /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enforces password complexity by requiring that at least one special character be used.
Note: The value to require a number of special characters to be set is expressed as a negative number in '/etc/security/pwquality.conf'.
Check the value for 'ocredit' in '/etc/security/pwquality.conf' with the following command:

# grep ocredit /etc/security/pwquality.conf

ocredit=-1
If the value of 'ocredit' is not set to a negative value, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^ocredit /etc/security/pwquality.conf)" == "ocredit = -1" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i ocredit /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "The 'difok' option sets the number of characters in a password that must not be present in the old password.
Check for the value of the 'difok' option in '/etc/security/pwquality.conf' with the following command:

# grep difok /etc/security/pwquality.conf

difok = 8
If the value of 'difok' is set to less than '8', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^difok /etc/security/pwquality.conf)" == "difok = 8" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i difok /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "The 'minclass' option sets the minimum number of required classes of characters for the new password (digits, upper-case, lower-case, others).
Check for the value of the 'minclass' option in '/etc/security/pwquality.conf' with the following command:

# grep minclass /etc/security/pwquality.conf

minclass = 4
If the value of 'minclass' is set to less than '4', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^minclass /etc/security/pwquality.conf)" == "minclass = 4" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i minclass /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "The 'maxrepeat' option sets the maximum number of allowed same consecutive characters in a new password.
Check for the value of the 'maxrepeat' option in '/etc/security/pwquality.conf' with the following command:

# grep maxrepeat /etc/security/pwquality.conf

maxrepeat = 2
If the value of 'maxrepeat' is set to more than '2', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^maxrepeat /etc/security/pwquality.conf)" == "maxrepeat = 2" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i maxrepeat /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "The 'maxclassrepeat' option sets the maximum number of allowed same consecutive characters in the same class in the new password.
Check for the value of the 'maxclassrepeat' option in '/etc/security/pwquality.conf' with the following command:

# grep maxclassrepeat /etc/security/pwquality.conf

maxclassrepeat = 4
If the value of 'maxclassrepeat' is set to more than '4', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
if [ "$(grep -i ^maxclassrepeat /etc/security/pwquality.conf)" == "maxclassrepeat = 4" ]; then
  echo "not a finding"
else
  echo "required manual check"
  grep -i maxclassrepeat /etc/security/pwquality.conf
fi

echo "___________________________________________________________________________________________________________________"
echo "Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.
Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep password /etc/pam.d/system-auth-ac

password sufficient pam_unix.so sha512
If the '/etc/pam.d/system-auth-ac' configuration files allow for password hashes other than SHA512 to be used, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep password /etc/pam.d/system-auth-ac
echo "___________________________________________________________________________________________________________________"
echo "Verify the system's shadow file is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.
Check that the system is configured to create SHA512 hashed passwords with the following command:

# grep -i encrypt /etc/login.defs

ENCRYPT_METHOD SHA512
If the '/etc/login.defs' configuration file does not exist or allows for password hashes other than SHA512 to be used, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i encrypt /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Verify the user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is 'SHA512'.
Check that the system is configured to create 'SHA512' hashed passwords with the following command:

# cat /etc/libuser.conf | grep -i sha512

crypt_style = sha512
If the 'crypt_style' variable is not set to 'sha512', is not in the defaults section, or does not exist, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
cat /etc/libuser.conf | grep -i sha512
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.
Check for the value of 'PASS_MIN_DAYS' in '/etc/login.defs' with the following command:

# grep -i pass_min_days /etc/login.defs

PASS_MIN_DAYS 1
If the 'PASS_MIN_DAYS' parameter value is not '1' or greater, or is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i pass_min_days /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Check whether the minimum time period between password changes for each user account is one day or greater.

# awk -F: '$4 < 1 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
awk -F: '$4 < 1 {print $1}' /etc/shadow
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.
Check for the value of 'PASS_MAX_DAYS' in '/etc/login.defs' with the following command:

# grep -i pass_max_days /etc/login.defs

PASS_MAX_DAYS 60
If the 'PASS_MAX_DAYS' parameter value is not 60 or less, or is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i pass_max_days /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Check whether the maximum time period for existing passwords is restricted to 60 days.

# awk -F: '$5 > 60 {print $1}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
awk -F: '$5 > 60 {print $1}' /etc/shadow
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prohibits password reuse for a minimum of five generations.
Check for the value of the 'remember' argument in '/etc/pam.d/system-auth-ac' with the following command:

# grep -i remember /etc/pam.d/system-auth-ac

password sufficient pam_unix.so use_authtok sha512 shadow remember=5
If the line containing the 'pam_unix.so' line does not have the 'remember' module argument set, or the value of the 'remember' module argument is set to less than '5', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i remember /etc/pam.d/system-auth-ac
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enforces a minimum 15-character password length. The 'minlen' option sets the minimum number of characters in a new password.
Check for the value of the 'minlen' option in '/etc/security/pwquality.conf' with the following command:

# grep minlen /etc/security/pwquality.conf

minlen = 15
If the command does not return a 'minlen' value of 15 or greater, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep minlen /etc/security/pwquality.conf
echo "___________________________________________________________________________________________________________________"
echo "To verify that null passwords cannot be used, run the following command:

# grep nullok /etc/pam.d/system-auth-ac

If this produces any output, it may be possible to log on with accounts with empty passwords.
If null passwords can be used, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep nullok /etc/pam.d/system-auth-ac
echo "___________________________________________________________________________________________________________________"
echo "To determine how the SSH daemon's 'PermitEmptyPasswords' option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

PermitEmptyPasswords no
If no line, a commented line, or a line indicating the value 'no' is returned, the required value is set.
If the required value is not set, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i PermitEmptyPasswords /etc/ssh/sshd_config
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:

# grep -i inactive /etc/default/useradd

INACTIVE=0
If the value is not set to '0', is commented out, or is not defined, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i inactive /etc/default/useradd
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system automatically locks an account for the maximum period for which the system can be configured.
Check that the system locks an account for the maximum period after three unsuccessful logon attempts within a period of 15 minutes with the following command:

# grep pam_faillock.so /etc/pam.d/password-auth-ac

auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800
If the 'unlock_time' setting is greater than '604800' on both lines with the 'pam_faillock.so' module name or is missing from a line, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep pam_faillock.so /etc/pam.d/password-auth-ac
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

# grep pam_faillock.so /etc/pam.d/password-auth-ac

auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900
If the 'even_deny_root' setting is not defined on both lines with the 'pam_faillock.so' module name, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep pam_faillock.so /etc/pam.d/password-auth-ac
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system requires users to supply a password for privilege escalation.
Check the configuration of the '/etc/sudoers' and '/etc/sudoers.d/*' files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any uncommented line is found with a 'NOPASSWD' tag, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i nopasswd /etc/sudoers /etc/sudoers.d/*
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system requires users to reauthenticate for privilege escalation.
Check the configuration of the '/etc/sudoers' and '/etc/sudoers.d/*' files with the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any line is found with a '!authenticate' tag, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i authenticate /etc/sudoers /etc/sudoers.d/*
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.
Check the value of the 'fail_delay' parameter in the '/etc/login.defs' file with the following command:

# grep -i fail_delay /etc/login.defs

FAIL_DELAY 4
If the value of 'FAIL_DELAY' is not set to '4' or greater, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i fail_delay /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check for the value of the 'AutomaticLoginEnable' in the '/etc/gdm/custom.conf' file with the following command:

# grep -i automaticloginenable /etc/gdm/custom.conf

AutomaticLoginEnable=false
If the value of 'AutomaticLoginEnable' is not set to 'false', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i automaticloginenable /etc/gdm/custom.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system does not allow an unrestricted logon to the system via a graphical user interface.
Note: If the system does not have GNOME installed, this requirement is Not Applicable.
Check for the value of the 'TimedLoginEnable' parameter in '/etc/gdm/custom.conf' file with the following command:

# grep -i timedloginenable /etc/gdm/custom.conf

TimedLoginEnable=false
If the value of 'TimedLoginEnable' is not set to 'false', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i timedloginenable /etc/gdm/custom.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system does not allow users to override environment variables to the SSH daemon.
Check for the value of the 'PermitUserEnvironment' keyword with the following command:

# grep -i permituserenvironment /etc/ssh/sshd_config

PermitUserEnvironment no
If the 'PermitUserEnvironment' keyword is not set to 'no', is missing, or is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i permituserenvironment /etc/ssh/sshd_config
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.
Check for the value of the 'HostbasedAuthentication' keyword with the following command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config

HostbasedAuthentication no
If the 'HostbasedAuthentication' keyword is not set to 'no', is missing, or is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i hostbasedauthentication /etc/ssh/sshd_config
echo "___________________________________________________________________________________________________________________"
echo "Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

# grep -i ^password_pbkdf2 /boot/grub2/grub.cfg

password_pbkdf2 superusers-account password-hash
If the root password entry does not begin with 'password_pbkdf2', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i ^password_pbkdf2 /boot/grub2/grub.cfg
echo "___________________________________________________________________________________________________________________"
echo "Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:

# grep -i password /boot/efi/EFI/redhat/grub.cfg

password_pbkdf2 superusers-account password-hash
If the root password entry does not begin with 'password_pbkdf2', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i password /boot/efi/EFI/redhat/grub.cfg
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication.
Check to see if smartcard authentication is enforced on the system:

# authconfig --test | grep -i smartcard

The entry for use only smartcard for logon may be enabled, and the smartcard module and smartcard removal actions must not be blank.
If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
authconfig --test | grep -i smartcard
echo "___________________________________________________________________________________________________________________"
echo "Check to see if the rsh-server package is installed with the following command:

# yum list installed rsh-server

If the rsh-server package is installed, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
yum list installed rsh-server
echo "___________________________________________________________________________________________________________________"
echo "The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.
Check to see if the 'ypserve' package is installed with the following command:

# yum list installed ypserv

If the 'ypserv' package is installed, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
yum list installed ypserv
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
Get a list of authorized users (other than System Administrator and guest accounts) for the system.
Check the list against the system by using the following command:

# semanage login -l | more

Login Name SELinux User MLS/MCS Range Service
__default__ user_u s0-s0:c0.c1023 *
root unconfined_u s0-s0:c0.c1023 *
system_u system_u s0-s0:c0.c1023 *
joe staff_u s0-s0:c0.c1023 *
All administrators must be mapped to the 'sysadm_u' or 'staff_u' users with the appropriate domains (sysadm_t and staff_t).
All authorized non-administrative users must be mapped to the 'user_u' role or the appropriate domain (user_t).
If they are not mapped in this way, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
semanage login -l | more
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system routinely checks the baseline configuration for unauthorized changes.
Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.
Check to see if AIDE is installed on the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the SA how file integrity checks are performed on the system.
Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.
Check the '/etc/cron.daily' subdirectory for a 'crontab' file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# ls -al /etc/cron.* | grep aide

-rwxr-xr-x 1 root root 29 Nov 22 2015 aide
If the file integrity application does not exist, or a 'crontab' file does not exist in the '/etc/cron.daily' or '/etc/cron.weekly' subdirectories, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"

yum list installed aide

ls -al /etc/cron.* | grep aide

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.
Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.
Check to see if AIDE is installed on the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the SA how file integrity checks are performed on the system.
Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.
Check the '/etc/cron.daily' subdirectory for a 'crontab' file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following commands:

# ls -al /etc/cron.daily | grep aide

-rwxr-xr-x 1 root root 32 Jul 1 2011 aide
AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:

# more /etc/cron.daily/aide

0 0 * * * /usr/sbin/aide --check | /bin/mail -s '$HOSTNAME - Daily aide integrity check run' root@sysname.mil
If the file integrity application does not notify designated personnel of changes, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"

yum list installed aide

ls -al /etc/cron.daily | grep aide

more /etc/cron.daily/aide

echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.
Check that yum verifies the signature of packages from a repository prior to install with the following command:

# grep gpgcheck /etc/yum.conf

gpgcheck=1

If 'gpgcheck' is not set to '1', or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.
If there is no process to validate certificates that is approved by the organization, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep gpgcheck /etc/yum.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.
Check that yum verifies the signature of local packages prior to install with the following command:

# grep localpkg_gpgcheck /etc/yum.conf

localpkg_gpgcheck=1
If 'localpkg_gpgcheck' is not set to '1', or if options are missing or commented out, ask the System Administrator how the signatures of local packages and other operating system components are verified.
If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep localpkg_gpgcheck /etc/yum.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification of the repository metadata.
Check that yum verifies the package metadata prior to install with the following command:

# grep repo_gpgcheck /etc/yum.conf

repo_gpgcheck=1
If 'repo_gpgcheck' is not set to '1', or if options are missing or commented out, ask the System Administrator how the metadata of local packages and other operating system components are verified.
If there is no process to validate the metadata of packages that is approved by the organization, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep repo_gpgcheck /etc/yum.conf
echo "___________________________________________________________________________________________________________________"
echo "If there is an HBSS with a Device Control Module and a Data Loss Prevention mechanism, this requirement is not applicable.
Verify the operating system disables the ability to use USB mass storage devices.
Check to see if USB mass storage is disabled with the following command:

# grep usb-storage /etc/modprobe.d/blacklist.conf

blacklist usb-storage
If the command does not return any output or the output is not 'blacklist usb-storage', and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep usb-storage /etc/modprobe.d/blacklist.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system disables the ability to automount devices.
Check to see if automounter service is active with the following command:

# systemctl status autofs

autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)
If the 'autofs' status is set to 'active' and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
systemctl status autofs
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system removes all software components after updated versions have been installed.
Check if yum is configured to remove unneeded packages with the following command:

# grep -i clean_requirements_on_remove /etc/yum.conf

clean_requirements_on_remove=1
If 'clean_requirements_on_remove' is not set to '1', 'True', or 'yes', or is not set in '/etc/yum.conf', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i clean_requirements_on_remove /etc/yum.conf
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system verifies correct operation of all security functions.
Check if 'SELinux' is active and in 'Enforcing' mode with the following command:

# getenforce

Enforcing
If 'SELinux' is not active and not in 'Enforcing' mode, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
getenforce
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system verifies correct operation of all security functions.
Check if 'SELinux' is active and is enforcing the targeted policy with the following command:

# sestatus

SELinux status: enabled
SELinuxfs mount: /selinu
XCurrent mode: enforcing
Mode from config file: enforcing
Policy version: 24
Policy from config file: targeted
If the 'Policy from config file' is not set to 'targeted', or the 'Loaded policy name' is not set to 'targeted', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
sestatus
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.
Check that the ctrl-alt-del.service is not active with the following command:

# systemctl status ctrl-alt-del.service

reboot.target - Reboot
Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
Active: inactive (dead)
Docs: man:systemd.special(7)
If the ctrl-alt-del.service is active, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
systemctl status ctrl-alt-del.service
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.
Check for the value of the 'UMASK' parameter in '/etc/login.defs' file with the following command:
Note: If the value of the 'UMASK' parameter is set to '000' in '/etc/login.defs' file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs

UMASK 077
If the value for the 'UMASK' parameter is not '077', or the 'UMASK' parameter is missing or is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i umask /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Verify the version of the operating system is vendor supported.
Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 7.2 (Maipo)
Current End of Life for RHEL 7.2 is Q4 2020.
Current End of Life for RHEL 7.3 is 30 June 2024.
If the release is not supported by the vendor, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
cat /etc/redhat-release
echo "___________________________________________________________________________________________________________________"
echo "Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).
Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.
Check that the available package security updates have been installed on the system with the following command:

# yum history list | more

Loaded plugins: langpacks, product-id, subscription-manager
ID | Command line | Date and time | Action(s) | Altered
-------------------------------------------------------------------------------
70 | install aide | 2016-05-05 10:58 | Install | 1
69 | update -y | 2016-05-04 14:34 | Update | 18 EE
68 | install vlc | 2016-04-21 17:12 | Install | 21
67 | update -y | 2016-04-21 17:04 | Update | 7 EE
66 | update -y | 2016-04-15 16:47 | E, I, U | 84 EE
If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding.
Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.
If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
yum history list | more
echo "___________________________________________________________________________________________________________________"
echo "Verify all accounts on the system are assigned to an active system, application, or user account.
Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).
Check the system accounts on the system with the following command:

# more /etc/passwd

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
Accounts such as 'games' and 'gopher' are not authorized accounts as they do not support authorized system functions.
If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
more /etc/passwd
echo "___________________________________________________________________________________________________________________"
echo "Verify all GIDs referenced in the '/etc/passwd' file are defined in the '/etc/group' file.
Check that all referenced GIDs exist with the following command:

# pwck -r

If GIDs referenced in '/etc/passwd' file are returned as not defined in '/etc/group' file, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
pwck -r
echo "___________________________________________________________________________________________________________________"
echo "Check the system for duplicate UID '0' assignments with the following command:

# awk -F: '$3 == 0 {print $1}' /etc/passwd

If any accounts other than root have a UID of '0', this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo "___________________________________________________________________________________________________________________"
echo "Verify all files and directories on the system have a valid owner.
Check the owner of all files and directories with the following command:
Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -xdev -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
find / -xdev -fstype xfs -nouser
echo "___________________________________________________________________________________________________________________"
echo "Verify all files and directories on the system have a valid group.
Check the owner of all files and directories with the following command:
Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -xdev -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
find / -xdev -fstype xfs -nogroup
echo "___________________________________________________________________________________________________________________"
echo "Verify local interactive users on the system have a home directory assigned.
Check for missing local interactive user home directories with the following command:

# pwck -r

user 'lp': directory '/var/spool/lpd' does not exist
user 'news': directory '/var/spool/news' does not exist
user 'uucp': directory '/var/spool/uucp' does not exist
user 'smithj': directory '/home/smithj' does not exist
Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ':[1-4][0-9]{2}$|:[0-9]{1,2}$'

If any interactive users do not have a home directory assigned, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"

pwck -r

cut -d: -f 1,3 /etc/passwd | egrep ':[1-4][0-9]{2}$|:[0-9]{1,2}$'

echo "___________________________________________________________________________________________________________________"
echo "Verify all local interactive users on the system are assigned a home directory upon creation.
Check to see if the system is configured to create home directories for local interactive users with the following command:

# grep -i create_home /etc/login.defs

CREATE_HOME yes
If the value for 'CREATE_HOME' parameter is not set to 'yes', the line is missing, or the line is commented out, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
grep -i create_home /etc/login.defs
echo "___________________________________________________________________________________________________________________"
echo "Verify the assigned home directory of all local interactive users on the system exists.
Check the home directory assignment for all local interactive non-privileged users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep ':[1-9][0-9]{2}$|:[0-9]{1,2}$'

smithj /home/smithj
Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.
Check that all referenced home directories exist with the following command:

# pwck -r

user 'smithj': directory '/home/smithj' does not exist
If any home directories referenced in '/etc/passwd' are returned as not defined, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"

cut -d: -f 1,3 /etc/passwd | egrep ':[1-9][0-9]{2}$|:[0-9]{1,2}$'

pwck -r

echo "___________________________________________________________________________________________________________________"
echo "Verify the assigned home directory of all local interactive users has a mode of '0750' or less permissive.
Check the home directory assignment for all non-privileged users on the system with the following command:
Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

# ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj
If home directories referenced in '/etc/passwd' do not have a mode of '0750' or less permissive, this is a finding."
echo "-------------------------------------------------------------------------------------------------------------------"
 ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)
