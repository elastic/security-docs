---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-bash-shell-profile-modification.html
---

# Bash Shell Profile Modification [prebuilt-rule-8-17-4-bash-shell-profile-modification]

Both ~/.bash_profile and ~/.bashrc are files containing shell commands that are run when Bash is invoked. These files are executed in a user’s context, either interactively or non-interactively, when a user logs in so that their environment is set correctly. Adversaries may abuse this to establish persistence by executing malicious content triggered by a user’s shell.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*
* auditbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat](https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat)

**Tags**:

* Domain: Endpoint
* OS: macOS
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3973]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Bash Shell Profile Modification**

Bash shell profiles, such as `.bash_profile` and `.bashrc`, are scripts that configure user environments upon login. Adversaries exploit these by inserting malicious commands to ensure persistence, executing harmful scripts whenever a user initiates a shell session. The detection rule identifies unauthorized modifications by monitoring file changes and filtering out benign processes, focusing on unusual executables and paths to flag potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific file path that was modified, focusing on paths like /home/**/.bash_profile or /home/**/.bashrc.
* Examine the process name and executable that triggered the alert to determine if it is an unusual or unauthorized process, as specified in the query.
* Check the modification timestamp of the affected file to correlate with any known user activity or scheduled tasks.
* Investigate the contents of the modified Bash shell profile file to identify any suspicious or unexpected commands or scripts.
* Cross-reference the user account associated with the modified file to determine if the activity aligns with their typical behavior or if the account may be compromised.
* Look for any related alerts or logs around the same timeframe that might indicate a broader attack or persistence mechanism.

**False positive analysis**

* Frequent use of text editors like vim or nano may trigger alerts when users legitimately modify their shell profiles. To mitigate this, consider excluding these processes from the detection rule if they are commonly used in your environment.
* Automated system updates or configuration management tools like dnf or yum might modify shell profiles as part of their operations. Exclude these processes if they are verified as part of routine maintenance.
* Development tools such as git or platform-python may alter shell profiles during setup or updates. If these tools are regularly used, add them to the exclusion list to prevent false positives.
* User-specific applications located in directories like /Applications or /usr/local may be flagged if they modify shell profiles. Verify these applications and exclude their paths if they are trusted and frequently used.
* Consider excluding specific user directories from monitoring if they are known to contain benign scripts that modify shell profiles, ensuring these exclusions are well-documented and reviewed regularly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified in the alert that are not part of the allowed list, such as unauthorized executables modifying shell profiles.
* Restore the modified shell profile files (.bash_profile, .bashrc) from a known good backup to remove any malicious entries.
* Conduct a thorough review of user accounts and permissions on the affected system to ensure no unauthorized access or privilege escalation has occurred.
* Implement file integrity monitoring on critical shell profile files to detect and alert on future unauthorized changes.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Review and update endpoint protection policies to enhance detection capabilities for similar persistence techniques, leveraging MITRE ATT&CK framework references for T1546.


## Rule query [_rule_query_4990]

```js
event.category:file and event.type:change and
  process.name:(* and not (sudo or vim or zsh or env or nano or bash or Terminal or xpcproxy or login or cat or cp or
  launchctl or java or dnf or tailwatchd or ldconfig or yum or semodule or cpanellogd or dockerd or authselect or chmod or
  dnf-automatic or git or dpkg or platform-python)) and
  not process.executable:(/Applications/* or /private/var/folders/* or /usr/local/* or /opt/saltstack/salt/bin/*) and
  file.path:(/private/etc/rc.local or
             /etc/rc.local or
             /home/*/.profile or
             /home/*/.profile1 or
             /home/*/.bash_profile or
             /home/*/.bash_profile1 or
             /home/*/.bashrc or
             /Users/*/.bash_profile or
             /Users/*/.zshenv)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Unix Shell Configuration Modification
    * ID: T1546.004
    * Reference URL: [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)



