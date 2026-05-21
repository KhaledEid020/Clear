* Run `/var/ossec/bin/wazuh-logtest` from the command line.

1. Paste the following log:

```
Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928
```

Output

```
**Phase 1: Completed pre-decoding.
   full event: 'Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928'
   timestamp: 'Oct 15 21:07:00'
   hostname: 'linux-agent'
   program_name: 'sshd'

**Phase 2: Completed decoding.
   name: 'sshd'
   parent: 'sshd'
   srcip: '18.18.18.18'
   srcport: '48928'
   srcuser: 'blimey'

**Phase 3: Completed filtering (rules).
   id: '5710'
   level: '5'
   description: 'sshd: Attempt to login using a non-existent user'
   groups: '["syslog","sshd","authentication_failed","invalid_login"]'
   firedtimes: '1'
   gdpr: '["IV_35.7.d","IV_32.2"]'
   gpg13: '["7.1"]'
   hipaa: '["164.312.b"]'
   mail: 'false'
   mitre.id: '["T1110.001","T1021.004","T1078"]'
   mitre.tactic: '["Credential Access","Lateral Movement","Defense Evasion","Persistence","Privilege Escalation","Initial Access"]'
   mitre.technique: '["Password Guessing","SSH","Valid Accounts"]'
   nist_800_53: '["AU.14","AC.7","AU.6"]'
   pci_dss: '["10.2.4","10.2.5","10.6.1"]'
   tsc: '["CC6.1","CC6.8","CC7.2","CC7.3"]'
**Alert to be generated.
```

The above result shows that rule id `5710` matches the event log.
If you paste the log six more times, you can see that rule id `5710` "sshd: Attempt to login using a non-existent user" matches each time. It is important to note that in Phase 3, filtering (rules), the `firedtimes` counter increases with each repetition. If you paste the log one more time, rule ID 5712 matches instead, indicating an attempted SSH brute force attack on the system. This rule triggers when there have been eight failed attempts to log in to SSH with a non-existing user, all originating from the same IP address, and occurring within a two-minute timeframe.

Output

```
**Phase 1: Completed pre-decoding.
     full event: 'Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928'
     timestamp: 'Oct 15 21:07:00'
     hostname: 'linux-agent'
     program_name: 'sshd'

**Phase 2: Completed decoding.
     name: 'sshd'
     parent: 'sshd'
     srcip: '18.18.18.18'
     srcport: '48928'
     srcuser: 'blimey'

**Phase 3: Completed filtering (rules).
     id: '5712'
     level: '10'
     description: 'sshd: brute force trying to get access to the system. Non existent user.'
     groups: '["syslog","sshd","authentication_failures"]'
     firedtimes: '1'
     frequency: '8'
     gdpr: '["IV_35.7.d","IV_32.2"]'
     hipaa: '["164.312.b"]'
     mail: 'false'
     mitre.id: '["T1110"]'
     mitre.tactic: '["Credential Access"]'
     mitre.technique: '["Brute Force"]'
     nist_800_53: '["SI.4","AU.14","AC.7"]'
     pci_dss: '["11.4","10.2.4","10.2.5"]'
     tsc: '["CC6.1","CC6.8","CC7.2","CC7.3"]'
**Alert to be generated.
```