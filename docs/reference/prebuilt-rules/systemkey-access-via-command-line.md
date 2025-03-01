---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/systemkey-access-via-command-line.html
---

# SystemKey Access via Command Line [systemkey-access-via-command-line]

Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos. Adversaries may collect the keychain storage data from a system to acquire credentials.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/AlessandroZ/LaZagne/blob/master/Mac/lazagne/softwares/system/chainbreaker.py](https://github.com/AlessandroZ/LaZagne/blob/master/Mac/lazagne/softwares/system/chainbreaker.py)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1063]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SystemKey Access via Command Line**

macOS keychains securely store user credentials, including passwords and certificates. Adversaries may exploit command-line access to extract keychain data, gaining unauthorized credentials. The detection rule identifies suspicious process activities targeting SystemKey paths, excluding legitimate security processes, to flag potential credential theft attempts.

**Possible investigation steps**

* Review the process details to identify the executable that attempted to access the SystemKey paths, focusing on the process.args field to confirm the presence of "/private/var/db/SystemKey" or "/var/db/SystemKey".
* Investigate the parent process using process.Ext.effective_parent.executable to determine if the process chain is suspicious or if it might be a legitimate process that was not excluded by the rule.
* Check the timestamp of the event to correlate with other system activities or user actions that might explain the access attempt.
* Analyze the user account associated with the process to determine if it aligns with expected behavior or if it might indicate a compromised account.
* Review recent system logs and security alerts for any other unusual activities or patterns that might suggest a broader compromise or targeted attack.
* If possible, conduct a forensic analysis of the system to identify any unauthorized changes or additional indicators of compromise related to credential theft.

**False positive analysis**

* Security software updates or scans may trigger the rule by accessing SystemKey paths. Users can create exceptions for known security applications that frequently access these paths, ensuring they are not flagged as threats.
* System maintenance scripts or backup processes might access SystemKey paths as part of routine operations. Identify these processes and add them to an exclusion list to prevent false alerts.
* Administrative tools used by IT departments for legitimate credential management could be mistakenly flagged. Verify these tools and configure the rule to exclude them from detection.
* Custom scripts developed for internal use that interact with keychain data should be reviewed and, if deemed safe, added to the list of exceptions to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule that are accessing the SystemKey paths, ensuring no further credential extraction occurs.
* Conduct a thorough review of the system’s keychain access logs to identify any unauthorized access attempts and determine the scope of the compromise.
* Change all credentials stored in the keychain that may have been accessed, including Wi-Fi passwords, website credentials, and any other sensitive information.
* Restore the system from a known good backup if unauthorized changes or persistent threats are detected, ensuring the system is free from compromise.
* Implement additional monitoring on the affected system and similar endpoints to detect any further attempts to access keychain data, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations team for further investigation and to assess the need for broader organizational response measures, such as notifying affected users or stakeholders.


## Setup [_setup_669]

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


## Rule query [_rule_query_1118]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.args:("/private/var/db/SystemKey" or "/var/db/SystemKey") and
  not process.Ext.effective_parent.executable : "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Keychain
    * ID: T1555.001
    * Reference URL: [https://attack.mitre.org/techniques/T1555/001/](https://attack.mitre.org/techniques/T1555/001/)



