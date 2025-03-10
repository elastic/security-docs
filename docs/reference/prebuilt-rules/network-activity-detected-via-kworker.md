---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/network-activity-detected-via-kworker.html
---

# Network Activity Detected via Kworker [network-activity-detected-via-kworker]

This rule monitors for network connections from a kworker process. kworker, or kernel worker, processes are part of the kernel’s workqueue mechanism. They are responsible for executing work that has been scheduled to be done in kernel space, which might include tasks like handling interrupts, background activities, and other kernel-related tasks. Attackers may attempt to evade detection by masquerading as a kernel worker process.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_572]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Activity Detected via Kworker**

Kworker processes are integral to Linux systems, handling kernel tasks like interrupts and background activities. Adversaries may exploit these processes to mask malicious network activities, evading detection by blending in with legitimate kernel operations. The detection rule identifies suspicious network connections initiated by kworker processes, excluding trusted IP ranges and ports, to uncover potential command and control activities.

**Possible investigation steps**

* Review the alert details to confirm the kworker process is indeed initiating network connections, focusing on the process.name field.
* Examine the destination IP address and port to determine if the connection is to an untrusted or suspicious external network, as the rule excludes trusted IP ranges and ports.
* Check historical data for any previous alerts or network activity involving the same kworker process to identify patterns or repeated behavior.
* Investigate the source host for any signs of compromise or unusual activity, such as unauthorized access attempts or unexpected process executions.
* Correlate the network activity with other security events or logs from the same timeframe to identify potential indicators of compromise or related malicious activities.

**False positive analysis**

* Network monitoring tools or legitimate applications may occasionally use kworker processes for routine checks or updates, leading to false positives. Users can create exceptions for these specific applications by identifying their typical IP ranges and ports.
* Internal network scanning or monitoring activities might trigger alerts. To mitigate this, users should exclude known internal IP ranges and ports used by these activities from the detection rule.
* Automated backup or synchronization services that operate in the background could be mistaken for suspicious activity. Users should identify these services and adjust the rule to exclude their associated network traffic.
* Some system updates or maintenance tasks might temporarily use kworker processes for network communication. Users can whitelist the IP addresses and ports associated with these tasks to prevent false alerts.
* If a specific kworker process consistently triggers alerts without any malicious intent, users should investigate the process’s behavior and, if deemed safe, add it to an exception list to avoid future false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and potential lateral movement by the attacker.
* Terminate any suspicious kworker processes identified as initiating unauthorized network connections to halt ongoing malicious activities.
* Conduct a thorough forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized files or processes, and remove them.
* Update and patch the affected system to the latest security standards to close any vulnerabilities that may have been exploited.
* Monitor network traffic for any further suspicious activity originating from other systems, indicating potential spread or persistence of the threat.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and logging for kworker processes and network activities to improve detection of similar threats in the future.


## Setup [_setup_370]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_613]

```js
host.os.type:linux and event.category:network and event.action:(connection_attempted or connection_accepted) and
process.name:kworker* and not destination.ip:(
  10.0.0.0/8 or
  127.0.0.0/8 or
  169.254.0.0/16 or
  172.16.0.0/12 or
  192.168.0.0/16 or
  224.0.0.0/4 or
  "::1" or
  "FE80::/10" or
  "FF00::/8" or
  "0.0.0.0"
) and not destination.port:("2049" or "111" or "892" or "597")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over C2 Channel
    * ID: T1041
    * Reference URL: [https://attack.mitre.org/techniques/T1041/](https://attack.mitre.org/techniques/T1041/)



