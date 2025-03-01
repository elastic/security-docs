---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/apple-script-execution-followed-by-network-connection.html
---

# Apple Script Execution followed by Network Connection [apple-script-execution-followed-by-network-connection]

Detects execution via the Apple script interpreter (osascript) followed by a network connection from the same process within a short time period. Adversaries may use malicious scripts for execution and command and control.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.md)
* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Command and Control
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_136]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Apple Script Execution followed by Network Connection**

AppleScript, a scripting language for macOS, automates tasks by controlling applications and system functions. Adversaries exploit it to execute scripts that establish unauthorized network connections, facilitating command and control activities. The detection rule identifies such abuse by monitoring the osascript process for script execution followed by network activity, excluding local and private IP ranges, within a short timeframe.

**Possible investigation steps**

* Review the process details for the osascript execution event, focusing on the process.entity_id and host.id to understand the context of the script execution.
* Examine the network connection details associated with the osascript process, particularly the destination IP address, to determine if it is known or suspicious, and check if it falls outside the excluded IP ranges.
* Investigate the script content or command line arguments used in the osascript execution to identify any potentially malicious or unexpected behavior.
* Check the timeline of events to see if there are any other related or suspicious activities occurring on the same host around the time of the osascript execution and network connection.
* Correlate the osascript activity with any other alerts or logs from the same host to identify patterns or additional indicators of compromise.
* Assess the user account associated with the osascript process to determine if it is a legitimate user or if there are signs of account compromise.

**False positive analysis**

* Legitimate automation scripts may trigger the rule if they execute osascript and establish network connections. Review the script’s purpose and source to determine if it is authorized.
* System management tools that use AppleScript for remote administration can cause false positives. Identify these tools and consider creating exceptions for their known processes.
* Software updates or applications that use AppleScript for network communication might be flagged. Verify the application’s legitimacy and update the rule to exclude these specific processes or IP addresses.
* Development environments that utilize AppleScript for testing or deployment may inadvertently match the rule. Ensure these environments are recognized and excluded from monitoring if they are trusted.
* Regularly review and update the list of excluded IP ranges and processes to ensure they reflect the current network and application landscape, minimizing unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS host from the network to prevent further unauthorized access or data exfiltration.
* Terminate the osascript process identified in the alert to stop any ongoing malicious activity.
* Conduct a thorough review of the executed AppleScript to identify any malicious commands or payloads and remove any associated files or scripts from the system.
* Reset credentials for any accounts that were accessed or could have been compromised during the incident.
* Apply security patches and updates to the macOS system to address any vulnerabilities that may have been exploited.
* Monitor network traffic for any further suspicious activity originating from the affected host or similar patterns across other systems.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_76]

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


## Rule query [_rule_query_138]

```js
sequence by host.id, process.entity_id with maxspan=30s
 [process where host.os.type == "macos" and event.type == "start" and process.name == "osascript"]
 [network where host.os.type == "macos" and event.type != "end" and process.name == "osascript" and destination.ip != "::1" and
  not cidrmatch(destination.ip,
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
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

    * Name: AppleScript
    * ID: T1059.002
    * Reference URL: [https://attack.mitre.org/techniques/T1059/002/](https://attack.mitre.org/techniques/T1059/002/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



