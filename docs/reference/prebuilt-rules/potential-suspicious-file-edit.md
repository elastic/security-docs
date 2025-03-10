---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-suspicious-file-edit.html
---

# Potential Suspicious File Edit [potential-suspicious-file-edit]

This rule monitors for the potential edit of a suspicious file. In Linux, when editing a file through an editor, a temporary .swp file is created. By monitoring for the creation of this .swp file, we can detect potential file edits of suspicious files. The execution of this rule is not a clear sign of the file being edited, as just opening the file through an editor will trigger this event. Attackers may alter any of the files added in this rule to establish persistence, escalate privileges or perform reconnaisance on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 1

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_782]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Suspicious File Edit**

In Linux environments, text editors create temporary swap files (.swp) during file editing. Adversaries exploit this by editing critical system files to maintain persistence or escalate privileges. The detection rule identifies the creation of .swp files in sensitive directories, signaling potential unauthorized file edits, thus alerting analysts to investigate further.

**Possible investigation steps**

* Review the alert details to identify the specific file path and name of the .swp file that triggered the alert, focusing on the directories and files listed in the query.
* Check the system logs and recent user activity to determine if there was any legitimate reason for editing the file, such as a scheduled maintenance or update.
* Investigate the user account associated with the file creation event to verify if the user has the necessary permissions and if their activity aligns with their role.
* Examine the contents of the original file (if accessible) and compare it with known baselines or backups to identify any unauthorized changes or anomalies.
* Look for other suspicious activities on the host, such as unusual login attempts, privilege escalation events, or the presence of other temporary files in sensitive directories.
* Assess the system for signs of persistence mechanisms or privilege escalation attempts, especially if the .swp file is associated with critical system files like /etc/shadow or /etc/passwd.

**False positive analysis**

* Editing non-sensitive files in monitored directories can trigger alerts. Users can create exceptions for specific directories or files that are frequently edited by authorized personnel.
* System administrators performing routine maintenance or updates may inadvertently create .swp files in sensitive directories. Implementing a whitelist for known maintenance activities can reduce false positives.
* Automated scripts or applications that open files in monitored directories for legitimate purposes can cause alerts. Identifying and excluding these processes from monitoring can help manage false positives.
* Developers working on configuration files in their home directories might trigger alerts. Excluding specific user directories or known development environments can mitigate these occurrences.
* Regular system updates or package installations might create temporary .swp files. Monitoring these activities and correlating them with update schedules can help distinguish between legitimate and suspicious activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes associated with the creation of the .swp files in sensitive directories to halt any ongoing malicious activity.
* Restore the affected files from a known good backup to ensure system integrity and remove any unauthorized changes.
* Conduct a thorough review of user accounts and permissions, especially those with elevated privileges, to identify and revoke any unauthorized access.
* Implement additional monitoring on the affected system and similar environments to detect any further attempts to edit critical files.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Review and update system hardening measures, such as file permissions and access controls, to prevent similar incidents in the future.


## Rule query [_rule_query_830]

```js
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and file.extension == "swp" and
file.path : (
  /* common interesting files and locations */
  "/etc/.shadow.swp", "/etc/.shadow-.swp", "/etc/.shadow~.swp", "/etc/.gshadow.swp", "/etc/.gshadow-.swp",
  "/etc/.passwd.swp", "/etc/.pwd.db.swp", "/etc/.master.passwd.swp", "/etc/.spwd.db.swp", "/etc/security/.opasswd.swp",
  "/etc/.environment.swp", "/etc/.profile.swp", "/etc/sudoers.d/.*.swp", "/etc/ld.so.conf.d/.*.swp",
  "/etc/init.d/.*.swp", "/etc/.rc.local.swp", "/etc/rc*.d/.*.swp", "/dev/shm/.*.swp", "/etc/update-motd.d/.*.swp",
  "/usr/lib/update-notifier/.*.swp",

  /* service, timer, want, socket and lock files */
  "/etc/systemd/system/.*.swp", "/usr/local/lib/systemd/system/.*.swp", "/lib/systemd/system/.*.swp",
  "/usr/lib/systemd/system/.*.swp","/home/*/.config/systemd/user/.*.swp", "/run/.*.swp", "/var/run/.*.swp/",

  /* profile and shell configuration files */
  "/home/*.profile.swp", "/home/*.bash_profile.swp", "/home/*.bash_login.swp", "/home/*.bashrc.swp", "/home/*.bash_logout.swp",
  "/home/*.zshrc.swp", "/home/*.zlogin.swp", "/home/*.tcshrc.swp", "/home/*.kshrc.swp", "/home/*.config.fish.swp",
  "/root/*.profile.swp", "/root/*.bash_profile.swp", "/root/*.bash_login.swp", "/root/*.bashrc.swp", "/root/*.bash_logout.swp",
  "/root/*.zshrc.swp", "/root/*.zlogin.swp", "/root/*.tcshrc.swp", "/root/*.kshrc.swp", "/root/*.config.fish.swp"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Sub-technique:

    * Name: RC Scripts
    * ID: T1037.004
    * Reference URL: [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)



