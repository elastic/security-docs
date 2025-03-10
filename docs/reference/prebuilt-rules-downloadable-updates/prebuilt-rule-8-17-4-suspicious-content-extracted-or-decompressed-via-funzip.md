---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-content-extracted-or-decompressed-via-funzip.html
---

# Suspicious Content Extracted or Decompressed via Funzip [prebuilt-rule-8-17-4-suspicious-content-extracted-or-decompressed-via-funzip]

Identifies when suspicious content is extracted from a file and subsequently decompressed using the funzip utility. Malware may execute the tail utility using the "-c" option to read a sequence of bytes from the end of a file. The output from tail can be piped to funzip in order to decompress malicious code before it is executed. This behavior is consistent with malware families such as Bundlore.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/software/S0482/](https://attack.mitre.org/software/S0482/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4418]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Content Extracted or Decompressed via Funzip**

Funzip is a utility used to decompress files directly from a stream, often employed in legitimate data processing tasks. However, adversaries can exploit this by combining it with the *tail* command to extract and execute malicious payloads stealthily. The detection rule identifies this misuse by monitoring specific command sequences and excluding benign processes, thus flagging potential threats for further investigation.

**Possible investigation steps**

* Review the process details to confirm the presence of the *tail* and *funzip* command sequence, focusing on the specific arguments used, such as "-c", to understand the context of the command execution.
* Examine the parent process information to determine if the process was initiated by any known benign executables or scripts, specifically checking against the exclusion list like "/usr/bin/dracut" or "/sbin/dracut".
* Investigate the command line history and execution context of the parent process, especially if it involves "sh" or "sudo", to identify any suspicious patterns or unauthorized script executions.
* Check the file path and content being accessed by the *tail* command to ensure it is not targeting sensitive or unexpected files, excluding known benign paths like "/var/log/messages".
* Correlate the event with other security alerts or logs from the same host to identify any related suspicious activities or patterns that might indicate a broader compromise.
* Assess the risk and impact by determining if the decompressed content was executed or if it led to any subsequent suspicious processes or network connections.

**False positive analysis**

* Legitimate system maintenance tasks may trigger this rule if they involve decompressing logs or data files using funzip. To manage this, identify and exclude specific maintenance scripts or processes that are known to use funzip in a non-threatening manner.
* Automated backup or data processing operations might use funzip in combination with tail for legitimate purposes. Review these operations and add exceptions for known benign processes or scripts that match this pattern.
* Security tools or monitoring solutions like Nessus may inadvertently trigger this rule if they use similar command sequences for scanning or data collection. Exclude these tools by adding exceptions for their specific command lines or parent processes.
* Custom scripts developed in-house for data analysis or processing might use funzip and tail together. Document these scripts and exclude them from the rule to prevent false positives, ensuring they are reviewed and approved by security teams.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of the potential malware.
* Terminate any suspicious processes identified by the detection rule, specifically those involving the *tail* and *funzip* command sequence.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious payloads.
* Review and analyze system logs and command history to identify any unauthorized access or additional malicious activities that may have occurred.
* Restore any compromised files or systems from known good backups to ensure integrity and availability of data.
* Implement application whitelisting to prevent unauthorized execution of utilities like *funzip* and *tail* by non-administrative users.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.


## Setup [_setup_1262]

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


## Rule query [_rule_query_5410]

```js
process where host.os.type == "linux" and event.action in ("exec", "exec_event", "start") and
((process.args == "tail" and process.args == "-c" and process.args == "funzip")) and
not process.args : "/var/log/messages" and
not process.parent.executable : ("/usr/bin/dracut", "/sbin/dracut", "/usr/bin/xargs") and
not (process.parent.name in ("sh", "sudo") and process.parent.command_line : "*nessus_su*")
```

**Framework**: MITRE ATT&CKTM

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



