---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-hex-payload-execution.html
---

# Potential Hex Payload Execution [potential-hex-payload-execution]

This rule detects potential hex payload execution on Linux systems. Adversaries may use hex encoding to obfuscate payloads and evade detection mechanisms.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
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
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_688]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Hex Payload Execution**

Hex encoding is often used in Linux environments to obfuscate data, making it harder for security tools to detect malicious payloads. Adversaries exploit this by encoding their payloads in hex to bypass security measures. The detection rule identifies suspicious processes like `xxd`, `python`, `php`, and others that use hex-related functions, signaling potential obfuscation attempts. By monitoring these patterns, the rule helps uncover hidden threats.

**Possible investigation steps**

* Review the process details, including the process name and command line arguments, to confirm if the execution aligns with typical hex decoding or encoding activities.
* Check the parent process of the suspicious process to understand the context of how the process was initiated and whether it was expected or part of a legitimate workflow.
* Investigate the user account associated with the process execution to determine if the activity is consistent with the user’s normal behavior or if the account may have been compromised.
* Examine the network activity associated with the process to identify any potential data exfiltration or communication with known malicious IP addresses.
* Look for any related file modifications or creations around the time of the process execution to identify if the decoded payload was written to disk or executed further.
* Cross-reference the alert with other security tools or logs, such as Crowdstrike or SentinelOne, to gather additional context or corroborating evidence of malicious activity.

**False positive analysis**

* Development and testing environments may frequently use hex encoding functions for legitimate purposes. To reduce noise, consider excluding processes running on known development servers from the rule.
* System administrators might use hex encoding tools like `xxd` for data conversion tasks. Identify and whitelist these routine administrative scripts to prevent false alerts.
* Automated scripts or applications that process data in hex format for encoding or decoding purposes can trigger this rule. Review and exclude these scripts if they are verified as non-malicious.
* Security tools or monitoring solutions themselves might use hex encoding for data analysis. Ensure these tools are recognized and excluded from triggering the rule.
* Regularly review and update the exclusion list to adapt to changes in the environment and ensure that only verified non-threatening behaviors are excluded.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potentially malicious payloads.
* Terminate any suspicious processes identified by the detection rule, such as those involving `xxd`, `python`, `php`, `ruby`, `perl`, or `lua` with hex-related functions.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious payloads or remnants.
* Review and analyze system logs and process execution history to determine the scope of the compromise and identify any additional affected systems.
* Restore the system from a known good backup if malicious activity is confirmed and cannot be fully remediated.
* Implement additional monitoring on the affected system and network to detect any recurrence of similar obfuscation attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.


## Setup [_setup_437]

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


## Rule query [_rule_query_728]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name == "xxd" and process.args like ("-r*", "-p*")) or
    (process.name like "python*" and process.command_line like "*fromhex*" and process.command_line like ("*decode*", "*encode*")) or
    (process.name like "php*" and process.command_line like "*hex2bin*") or
    (process.name like "ruby*" and process.command_line like "*].pack(\"H*\")*") or
    (process.name like "perl*" and process.command_line like "*pack(\"H*\",*") or
    (process.name like "lua*" and process.command_line like "*tonumber(cc, 16)*")
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



