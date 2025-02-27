---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-kerberos-attack-via-bifrost.html
---

# Potential Kerberos Attack via Bifrost [potential-kerberos-attack-via-bifrost]

Identifies use of Bifrost, a known macOS Kerberos pentesting tool, which can be used to dump cached Kerberos tickets or attempt unauthorized authentication techniques such as pass-the-ticket/hash and kerberoasting.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/its-a-feature/bifrost](https://github.com/its-a-feature/bifrost)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_694]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Kerberos Attack via Bifrost**

Kerberos is a network authentication protocol designed to provide secure identity verification for users and services. Adversaries exploit tools like Bifrost on macOS to extract Kerberos tickets or perform unauthorized authentications, such as pass-the-ticket attacks. The detection rule identifies suspicious process activities linked to Bifrost’s known attack methods, focusing on specific command-line arguments indicative of credential access and lateral movement attempts.

**Possible investigation steps**

* Review the process start event details to identify the specific command-line arguments used, focusing on those that match the suspicious patterns such as "-action", "-kerberoast", "askhash", "asktgs", "asktgt", "s4u", "-ticket ptt", or "dump tickets/keytab".
* Correlate the process execution with user activity logs to determine if the process was initiated by a legitimate user or an unauthorized account.
* Check for any recent changes in user permissions or group memberships that could indicate privilege escalation attempts.
* Investigate the source and destination of any network connections made by the process to identify potential lateral movement or data exfiltration.
* Analyze historical data for similar process executions or patterns to assess if this is an isolated incident or part of a broader attack campaign.
* Review endpoint security logs for any additional indicators of compromise or related suspicious activities around the time of the alert.

**False positive analysis**

* Legitimate administrative tasks on macOS systems may trigger the rule if they involve Kerberos ticket management. To handle this, identify and document routine administrative processes that use similar command-line arguments and create exceptions for these specific activities.
* Security tools or scripts designed for Kerberos ticket management or testing may mimic Bifrost’s behavior. Review and whitelist these tools if they are part of authorized security assessments or IT operations.
* Automated system processes that interact with Kerberos for legitimate authentication purposes might be flagged. Monitor these processes and exclude them from the rule if they are verified as non-threatening and essential for system operations.
* Developers or IT personnel testing Kerberos configurations in a controlled environment could inadvertently trigger the rule. Ensure that such environments are well-documented and excluded from monitoring to prevent false positives.

**Response and remediation**

* Immediately isolate the affected macOS host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified by the detection rule, particularly those involving Bifrost command-line arguments.
* Conduct a thorough review of Kerberos ticket logs and authentication attempts to identify any unauthorized access or anomalies.
* Revoke and reissue Kerberos tickets for affected users and services to ensure no compromised tickets are in use.
* Update and patch the macOS system and any related software to mitigate vulnerabilities that may have been exploited.
* Implement enhanced monitoring for Kerberos-related activities, focusing on unusual patterns or command-line arguments similar to those used by Bifrost.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Setup [_setup_442]

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


## Rule query [_rule_query_734]

```js
event.category:process and host.os.type:macos and event.type:start and
 process.args:("-action" and ("-kerberoast" or askhash or asktgs or asktgt or s4u or ("-ticket" and ptt) or (dump and (tickets or keytab))))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Pass the Ticket
    * ID: T1550.003
    * Reference URL: [https://attack.mitre.org/techniques/T1550/003/](https://attack.mitre.org/techniques/T1550/003/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

* Sub-technique:

    * Name: Kerberoasting
    * ID: T1558.003
    * Reference URL: [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)



