---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/ssh-authorized-keys-file-modification.html
---

# SSH Authorized Keys File Modification [ssh-authorized-keys-file-modification]

The Secure Shell (SSH) authorized_keys file specifies which users are allowed to log into a server using public key authentication. Adversaries may modify it to maintain persistence on a victim host by adding their own public key(s).

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_893]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSH Authorized Keys File Modification**

SSH authorized_keys files are crucial for secure, password-less authentication, allowing users to log into servers using public keys. Adversaries exploit this by adding their keys, ensuring persistent access. The detection rule identifies unauthorized changes to these files, excluding benign processes, to flag potential threats, focusing on persistence and lateral movement tactics.

**Possible investigation steps**

* Review the alert details to identify the specific file that was modified, focusing on "authorized_keys", "authorized_keys2", "/etc/ssh/sshd_config", or "/root/.ssh".
* Examine the process that triggered the alert by checking the process executable path to ensure it is not one of the benign processes listed in the exclusion criteria.
* Investigate the user account associated with the modification to determine if it is a legitimate user or potentially compromised.
* Check the timestamp of the file modification to correlate with any known user activity or scheduled tasks that might explain the change.
* Analyze recent login attempts and SSH connections to the server to identify any suspicious activity or unauthorized access.
* Review the contents of the modified authorized_keys file to identify any unfamiliar or unauthorized public keys that have been added.
* If unauthorized keys are found, remove them and consider resetting credentials or keys for affected accounts to prevent further unauthorized access.

**False positive analysis**

* Development tools like git and maven may modify SSH authorized_keys files during legitimate operations. To prevent these from triggering alerts, add their paths to the exclusion list in the detection rule.
* System utilities such as vim and touch are often used by administrators to manually update authorized_keys files. Consider excluding these processes if they are part of regular maintenance activities.
* Automation tools like puppet and chef-client might update SSH configurations as part of their deployment scripts. Verify these changes are expected and exclude these processes if they are part of routine operations.
* Docker-related processes may alter SSH configurations when containers are being managed. If these changes are part of standard container operations, include the relevant paths in the exclusion list.
* Google Guest Agent and JumpCloud Agent might modify SSH settings as part of their management tasks. Confirm these actions are legitimate and exclude these processes if they align with normal system management activities.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Review the SSH authorized_keys file and remove any unauthorized or suspicious public keys that have been added.
* Change the passwords for all user accounts on the affected host to prevent adversaries from regaining access using compromised credentials.
* Conduct a thorough review of user accounts and permissions on the affected host to identify and disable any unauthorized accounts or privilege escalations.
* Restore the affected system from a known good backup if unauthorized changes are extensive or if the integrity of the system is in question.
* Implement additional monitoring on the affected host and network to detect any further unauthorized access attempts or suspicious activities.
* Escalate the incident to the security operations team for further investigation and to determine if other systems may be affected.


## Rule query [_rule_query_949]

```js
event.category:file and event.type:(change or creation) and
 file.name:("authorized_keys" or "authorized_keys2" or "/etc/ssh/sshd_config" or "/root/.ssh") and
 not process.executable:
             (/Library/Developer/CommandLineTools/usr/bin/git or
              /usr/local/Cellar/maven/*/libexec/bin/mvn or
              /Library/Java/JavaVirtualMachines/jdk*.jdk/Contents/Home/bin/java or
              /usr/bin/vim or
              /usr/local/Cellar/coreutils/*/bin/gcat or
              /usr/bin/bsdtar or
              /usr/bin/nautilus or
              /usr/bin/scp or
              /usr/bin/touch or
              /var/lib/docker/* or
              /usr/bin/google_guest_agent or
              /opt/jc/bin/jumpcloud-agent or
              /opt/puppetlabs/puppet/bin/puppet or
              /usr/bin/chef-client
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)



