---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-network-connection-via-sudo-binary.html
---

# Network Connection via Sudo Binary [prebuilt-rule-8-17-4-network-connection-via-sudo-binary]

Detects network connections initiated by the "sudo" binary. This behavior is uncommon and may occur in instances where reverse shell shellcode is injected into a process run with elevated permissions via "sudo". Attackers may attempt to inject shellcode into processes running as root, to escalate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4526]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Connection via Sudo Binary**

The *sudo* command in Linux allows users to execute commands with elevated privileges, typically as the root user. Adversaries may exploit this by injecting malicious shellcode into processes running with these privileges, potentially establishing unauthorized network connections. The detection rule identifies unusual network activity initiated by *sudo*, excluding common internal IP ranges, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific destination IP address involved in the network connection attempt. Cross-reference this IP with known malicious IP databases or threat intelligence sources to assess potential risk.
* Examine the process tree and command line arguments associated with the *sudo* process to determine if there are any unusual or unexpected commands being executed that could indicate malicious activity.
* Check the user account that initiated the *sudo* command to verify if it is a legitimate user and if there have been any recent changes to user permissions or roles that could explain the activity.
* Investigate any recent login attempts or authentication logs for the user account involved to identify any suspicious access patterns or failed login attempts that could suggest a compromised account.
* Analyze network traffic logs around the time of the alert to identify any other unusual outbound connections or data exfiltration attempts that may correlate with the *sudo* network connection event.

**False positive analysis**

* Internal network monitoring tools may trigger this rule if they use the sudo command to initiate legitimate network connections. To handle this, identify the specific tools and processes involved and create exceptions for their known IP addresses.
* Automated scripts or cron jobs running with elevated privileges might occasionally establish network connections for updates or data transfers. Review these scripts and whitelist their expected behavior to prevent false positives.
* System administrators using sudo for remote management tasks could inadvertently trigger the rule. Document and exclude the IP addresses and processes associated with routine administrative tasks.
* Security software or agents that require elevated permissions to perform network diagnostics or reporting may cause alerts. Verify these applications and add them to an exception list if they are deemed safe and necessary for operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes associated with the *sudo* command that are attempting to establish network connections.
* Conduct a thorough review of system logs and network traffic to identify any additional indicators of compromise or lateral movement attempts.
* Reset credentials for any accounts that may have been compromised, particularly those with elevated privileges.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Restore the system from a known good backup if malicious activity is confirmed and system integrity is compromised.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1358]

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
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5518]

```js
sequence by host.id, process.entity_id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec"]
  [network where host.os.type == "linux" and event.type == "start" and
  event.action in ("connection_attempted", "ipv4_connection_attempt_event") and process.name == "sudo" and not (
    destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
      destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
      "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
      "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
      "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
      "FF00::/8", "172.31.0.0/16"
    )
  )]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Ptrace System Calls
    * ID: T1055.008
    * Reference URL: [https://attack.mitre.org/techniques/T1055/008/](https://attack.mitre.org/techniques/T1055/008/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)



