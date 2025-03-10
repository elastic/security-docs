---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-linux-hack-tool-launched.html
---

# Potential Linux Hack Tool Launched [prebuilt-rule-8-17-4-potential-linux-hack-tool-launched]

Monitors for the execution of different processes that might be used by attackers for malicious intent. An alert from this rule should be investigated further, as hack tools are commonly used by blue teamers and system administrators as well.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4401]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Linux Hack Tool Launched**

Linux environments often utilize various tools for system administration and security testing. While these tools serve legitimate purposes, adversaries can exploit them for malicious activities, such as unauthorized access or data exfiltration. The detection rule identifies suspicious process executions linked to known hacking tools, flagging potential misuse by monitoring specific process names and actions indicative of exploitation attempts.

**Possible investigation steps**

* Review the process name that triggered the alert to determine if it matches any known hacking tools listed in the query, such as "crackmapexec" or "sqlmap".
* Check the user account associated with the process execution to assess if it is a legitimate user or potentially compromised.
* Investigate the source and destination IP addresses involved in the process execution to identify any unusual or unauthorized network activity.
* Examine the command line arguments used during the process execution to understand the intent and scope of the activity.
* Correlate the event with other logs or alerts from the same host to identify any patterns or additional suspicious activities.
* Verify if the process execution aligns with any scheduled tasks or known administrative activities to rule out false positives.

**False positive analysis**

* System administrators and security teams often use tools like "john", "hashcat", and "hydra" for legitimate security testing and password recovery. To reduce false positives, create exceptions for these tools when used by authorized personnel or during scheduled security assessments.
* Blue team exercises may involve the use of exploitation frameworks such as "msfconsole" and "msfvenom". Implement a process to whitelist these activities when they are part of a sanctioned security drill.
* Network scanning tools like "zenmap" and "nuclei" are frequently used for network mapping and vulnerability assessments. Establish a baseline of normal usage patterns and exclude these from alerts when they match expected behavior.
* Web enumeration tools such as "gobuster" and "dirbuster" might be used by web developers for testing purposes. Coordinate with development teams to identify legitimate use cases and exclude these from triggering alerts.
* Regularly review and update the list of excluded processes to ensure that only non-threatening activities are exempted, maintaining a balance between security and operational efficiency.

**Response and remediation**

* Immediately isolate the affected Linux host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the alert, such as those listed in the detection query, to halt potential malicious activities.
* Conduct a thorough review of system logs and process execution history to identify any additional indicators of compromise or lateral movement attempts.
* Restore the affected system from a known good backup if any unauthorized changes or data exfiltration are confirmed.
* Update and patch all software and applications on the affected host to mitigate vulnerabilities that could be exploited by the identified tools.
* Implement stricter access controls and monitoring on the affected host to prevent unauthorized execution of potentially malicious tools in the future.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems may be affected.


## Setup [_setup_1245]

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


## Rule query [_rule_query_5393]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in~ (
  // exploitation frameworks
  "crackmapexec", "msfconsole", "msfvenom", "sliver-client", "sliver-server", "havoc",
  // network scanners (nmap left out to reduce noise)
  "zenmap", "nuclei", "netdiscover", "legion",
  // web enumeration
  "gobuster", "dirbuster", "dirb", "wfuzz", "ffuf", "whatweb", "eyewitness",
  // web vulnerability scanning
  "wpscan", "joomscan", "droopescan", "nikto",
  // exploitation tools
  "sqlmap", "commix", "yersinia",
  // cracking and brute forcing
  "john", "hashcat", "hydra", "ncrack", "cewl", "fcrackzip", "rainbowcrack",
  // host and network
  "linenum.sh", "linpeas.sh", "pspy32", "pspy32s", "pspy64", "pspy64s", "binwalk", "evil-winrm",
  "linux-exploit-suggester-2.pl", "linux-exploit-suggester.sh", "panix.sh"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



