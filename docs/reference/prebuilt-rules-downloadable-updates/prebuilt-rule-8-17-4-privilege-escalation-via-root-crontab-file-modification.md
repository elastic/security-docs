---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-privilege-escalation-via-root-crontab-file-modification.html
---

# Privilege Escalation via Root Crontab File Modification [prebuilt-rule-8-17-4-privilege-escalation-via-root-crontab-file-modification]

Identifies modifications to the root crontab file. Adversaries may overwrite this file to gain code execution with root privileges by exploiting privileged file write or move related vulnerabilities.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://phoenhex.re/2017-06-09/pwn2own-diskarbitrationd-privesc](https://phoenhex.re/2017-06-09/pwn2own-diskarbitrationd-privesc)
* [https://www.exploit-db.com/exploits/42146](https://www.exploit-db.com/exploits/42146)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4606]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via Root Crontab File Modification**

Crontab files in macOS are used to schedule tasks, often requiring elevated privileges for execution. Adversaries exploit this by modifying the root crontab file, enabling unauthorized code execution with root access. The detection rule identifies suspicious modifications to this file, excluding legitimate crontab processes, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to confirm the file path involved is /private/var/at/tabs/root, as this is the specific file path targeted by the rule.
* Examine the process that modified the root crontab file by checking the process executable path. Ensure it is not /usr/bin/crontab, which is excluded as a legitimate process.
* Investigate the user account associated with the process that made the modification to determine if it has legitimate access or if it might be compromised.
* Check for any recent changes or anomalies in user account activity or permissions that could indicate unauthorized access or privilege escalation attempts.
* Correlate this event with other security alerts or logs from the same host to identify any patterns or additional suspicious activities that might suggest a broader attack campaign.
* Assess the risk and impact of the modification by determining if any unauthorized or malicious tasks have been scheduled in the crontab file.

**False positive analysis**

* System maintenance tasks or updates may modify the root crontab file. To handle these, users can create exceptions for known maintenance processes that are verified as safe.
* Administrative scripts that require scheduled tasks might trigger this rule. Users should document and exclude these scripts if they are part of regular, authorized operations.
* Backup or monitoring software that interacts with crontab files could cause false positives. Verify these applications and exclude their processes if they are legitimate and necessary for system operations.
* Custom automation tools used by IT departments might modify crontab files. Ensure these tools are reviewed and whitelisted if they are part of approved workflows.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or execution of malicious tasks.
* Review the modified root crontab file to identify any unauthorized or suspicious entries and remove them to stop any malicious scheduled tasks.
* Conduct a thorough investigation to determine how the crontab file was modified, focusing on identifying any exploited vulnerabilities or unauthorized access points.
* Reset credentials and review permissions for any accounts that may have been compromised or used in the attack to prevent further unauthorized access.
* Apply security patches and updates to the operating system and any vulnerable applications to close exploited vulnerabilities.
* Monitor the system and network for any signs of continued unauthorized activity or attempts to modify crontab files, using enhanced logging and alerting mechanisms.
* Escalate the incident to the appropriate internal security team or external cybersecurity experts if the threat persists or if there is evidence of a broader compromise.


## Setup [_setup_1438]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5598]

```js
event.category:file and host.os.type:macos and not event.type:deletion and
 file.path:/private/var/at/tabs/root and not process.executable:/usr/bin/crontab
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)



