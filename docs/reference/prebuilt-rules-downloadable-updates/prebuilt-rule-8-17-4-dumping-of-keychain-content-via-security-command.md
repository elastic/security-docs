---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dumping-of-keychain-content-via-security-command.html
---

# Dumping of Keychain Content via Security Command [prebuilt-rule-8-17-4-dumping-of-keychain-content-via-security-command]

Adversaries may dump the content of the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://ss64.com/osx/security.html](https://ss64.com/osx/security.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4547]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Dumping of Keychain Content via Security Command**

Keychains in macOS securely store user credentials, including passwords and certificates. Adversaries exploit this by using commands to extract keychain data, aiming to access sensitive information. The detection rule identifies suspicious activity by monitoring processes that initiate keychain dumps, specifically looking for command-line arguments associated with this malicious behavior, thus alerting analysts to potential credential theft attempts.

**Possible investigation steps**

* Review the process details to identify the parent process and determine if the keychain dump was initiated by a legitimate application or user.
* Examine the user account associated with the process to verify if the activity aligns with their typical behavior or if the account may be compromised.
* Check the timestamp of the event to correlate with any other suspicious activities or anomalies on the system around the same time.
* Investigate the command-line arguments used in the process to confirm if they match known patterns of malicious keychain dumping attempts.
* Analyze any network connections or data transfers initiated by the process to identify potential exfiltration of the dumped keychain data.
* Look for additional alerts or logs from the same host or user to assess if this is part of a broader attack campaign.

**False positive analysis**

* Legitimate administrative tasks or system maintenance activities may trigger the rule if they involve keychain access. Users should review the context of the process initiation to determine if it aligns with routine administrative operations.
* Security or IT tools that perform regular audits or backups of keychain data might be flagged. Users can create exceptions for these tools by identifying their specific process names or paths and excluding them from the rule.
* Developers or advanced users testing applications that require keychain access might inadvertently trigger the rule. Users should document these activities and consider temporary exclusions during development phases.
* Automated scripts or workflows that interact with keychain data for legitimate purposes could be mistaken for malicious activity. Users should ensure these scripts are well-documented and consider adding them to an allowlist if they are frequently used.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, specifically those involving the "dump-keychain" command, to halt ongoing credential theft attempts.
* Conduct a thorough review of the system’s keychain access logs to identify any unauthorized access or export of credentials and determine the scope of the compromise.
* Change all credentials stored in the keychain, including passwords for Wi-Fi, websites, and any other services, to mitigate the risk of unauthorized access using stolen credentials.
* Restore the system from a known good backup if any unauthorized changes or malware are detected, ensuring that the backup predates the compromise.
* Escalate the incident to the security operations team for further investigation and to assess whether additional systems may be affected.
* Implement enhanced monitoring and alerting for similar suspicious activities, focusing on keychain access and command-line arguments related to credential dumping, to prevent future incidents.


## Setup [_setup_1379]

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


## Rule query [_rule_query_5539]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
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



