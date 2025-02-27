---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-kerberos-cached-credentials-dumping.html
---

# Kerberos Cached Credentials Dumping [prebuilt-rule-8-17-4-kerberos-cached-credentials-dumping]

Identifies the use of the Kerberos credential cache (kcc) utility to dump locally cached Kerberos tickets. Adversaries may attempt to dump credential material in the form of tickets that can be leveraged for lateral movement.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/kerberosdump.py](https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/kerberosdump.py)
* [https://opensource.apple.com/source/Heimdal/Heimdal-323.12/kuser/kcc-commands.in.auto.html](https://opensource.apple.com/source/Heimdal/Heimdal-323.12/kuser/kcc-commands.in.auto.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4549]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kerberos Cached Credentials Dumping**

Kerberos is a network authentication protocol designed to provide secure identity verification for users and services. It uses tickets to allow nodes to prove their identity in a secure manner. Adversaries may exploit tools like the Kerberos credential cache utility to extract these tickets, enabling unauthorized access and lateral movement within a network. The detection rule identifies suspicious activity by monitoring for specific processes and arguments on macOS systems, flagging potential credential dumping attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of the process name *kcc* and the argument *copy_cred_cache* in the process execution logs on macOS systems.
* Identify the user account associated with the process execution to determine if the activity aligns with expected behavior or if it indicates potential unauthorized access.
* Examine the timeline of the process execution to identify any preceding or subsequent suspicious activities, such as unusual login attempts or lateral movement within the network.
* Check for any other alerts or logs related to the same host or user account to assess if this is part of a broader attack pattern.
* Investigate the source and destination of any network connections made by the process to identify potential data exfiltration or communication with known malicious IP addresses.
* Consult with the user or system owner to verify if the use of the *kcc* utility was legitimate or if it requires further investigation.

**False positive analysis**

* Routine administrative tasks using the kcc utility may trigger the rule. Identify and document these tasks to create exceptions for known benign activities.
* Automated scripts or maintenance processes that involve copying Kerberos credential caches can be mistaken for malicious activity. Review and whitelist these scripts if they are verified as safe.
* Developers or IT personnel testing Kerberos configurations might use the kcc utility in a non-malicious context. Establish a process to log and approve such activities to prevent false alarms.
* Security tools or monitoring solutions that interact with Kerberos tickets for legitimate purposes may inadvertently trigger the rule. Coordinate with security teams to ensure these tools are recognized and excluded from detection.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement.
* Terminate the suspicious process identified as *kcc* with the argument *copy_cred_cache* to stop any ongoing credential dumping activity.
* Conduct a thorough review of the system’s Kerberos ticket cache to identify any unauthorized access or anomalies, and invalidate any compromised tickets.
* Reset passwords and regenerate Kerberos tickets for any accounts that may have been affected to prevent further unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring on the affected system and similar endpoints to detect any recurrence of the credential dumping activity.
* Review and update access controls and Kerberos configurations to enhance security and reduce the risk of similar attacks in the future.


## Setup [_setup_1381]

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


## Rule query [_rule_query_5541]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.name:kcc and
  process.args:copy_cred_cache
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

* Sub-technique:

    * Name: Kerberoasting
    * ID: T1558.003
    * Reference URL: [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)



