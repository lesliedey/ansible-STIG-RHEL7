# ansible-STIG-RHEL7
my ansible scripts for STIGing RHEL7

use this command to run the playbook
```
ansible-playbook -k -i hosts stig.yml
```

use this command if you only want to run all stigs with the level of cat1
```
ansible-playbook -k -i hosts stig.yml --tags "cat1"
```

