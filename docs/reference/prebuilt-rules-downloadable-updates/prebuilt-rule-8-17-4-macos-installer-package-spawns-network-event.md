---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-macos-installer-package-spawns-network-event.html
---

# MacOS Installer Package Spawns Network Event [prebuilt-rule-8-17-4-macos-installer-package-spawns-network-event]

Detects the execution of a MacOS installer package with an abnormal child process (e.g bash) followed immediately by a network connection via a suspicious process (e.g curl). Threat actors will build and distribute malicious MacOS installer packages, which have a .pkg extension, many times imitating valid software in order to persuade and infect their victims often using the package files (e.g pre/post install scripts etc.) to download additional tools or malicious software. If this rule fires it should indicate the installation of a malicious or suspicious package.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://redcanary.com/blog/clipping-silver-sparrows-wings](https://redcanary.com/blog/clipping-silver-sparrows-wings)
* [https://posts.specterops.io/introducing-mystikal-4fbd2f7ae520](https://posts.specterops.io/introducing-mystikal-4fbd2f7ae520)
* [https://github.com/D00MFist/Mystikal](https://github.com/D00MFist/Mystikal)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4570]

**Triage and analysis**

[TBC: QUOTE]
**Investigating MacOS Installer Package Spawns Network Event**

MacOS installer packages, often with a .pkg extension, are used to distribute software. Adversaries exploit this by embedding scripts to execute additional commands or download malicious payloads. The detection rule identifies suspicious behavior by monitoring for installer packages spawning shell processes followed by network activity, indicating potential malicious activity.

**Possible investigation steps**

* Review the process details to identify the parent process name and entity ID, focusing on processes like "installer" or "package_script_service" that initiated the suspicious activity.
* Examine the child process that was spawned, such as "bash", "sh", or "python", to determine the commands executed and assess if they align with typical installation behavior or appear malicious.
* Investigate the network activity associated with the suspicious process, particularly looking at processes like "curl" or "wget", to identify any external connections made and the destination IP addresses or domains.
* Check the timestamp and sequence of events to confirm if the network activity closely followed the process execution, indicating a potential download or data exfiltration attempt.
* Analyze any downloaded files or payloads for malicious content using threat intelligence tools or sandbox environments to determine their intent and potential impact.
* Correlate the findings with known threat actor tactics or campaigns, leveraging threat intelligence sources to assess if the activity matches any known patterns or indicators of compromise.

**False positive analysis**

* Legitimate software installations may trigger this rule if they use scripts to configure network settings or download updates. Users can create exceptions for known safe software by whitelisting specific installer package names or hashes.
* System administrators often use scripts to automate software deployment and updates, which might involve network activity. To reduce false positives, exclude processes initiated by trusted administrative tools or scripts.
* Development environments on macOS might execute scripts that connect to the internet for dependencies or updates. Users can mitigate this by excluding processes associated with known development tools or environments.
* Some security tools or monitoring software may use scripts to perform network checks or updates. Identify and exclude these processes if they are verified as non-threatening.
* Frequent updates from trusted software vendors might trigger this rule. Users should maintain an updated list of trusted vendors and exclude their processes from triggering alerts.

**Response and remediation**

* Isolate the affected MacOS system from the network immediately to prevent further malicious activity or data exfiltration.
* Terminate any suspicious processes identified in the alert, such as those initiated by the installer package, to halt ongoing malicious actions.
* Conduct a thorough review of the installed applications and remove any unauthorized or suspicious software, especially those with a .pkg extension.
* Restore the system from a known good backup if available, ensuring that the backup predates the installation of the malicious package.
* Update and patch the MacOS system and all installed applications to the latest versions to mitigate vulnerabilities that could be exploited by similar threats.
* Monitor network traffic for any signs of command and control communication or data exfiltration attempts, using the indicators identified in the alert.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1402]

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


## Rule query [_rule_query_5562]

```js
sequence by host.id with maxspan=15s
[process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and process.parent.name : ("installer", "package_script_service") and process.name : ("bash", "sh", "zsh", "python", "osascript", "tclsh*")] by process.entity_id
[network where host.os.type == "macos" and event.type == "start" and process.name : ("curl", "osascript", "wget", "python", "java", "ruby", "node")] by process.parent.entity_id
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

    * Name: JavaScript
    * ID: T1059.007
    * Reference URL: [https://attack.mitre.org/techniques/T1059/007/](https://attack.mitre.org/techniques/T1059/007/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)



