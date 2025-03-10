---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-browser-child-process.html
---

# Suspicious Browser Child Process [prebuilt-rule-8-17-4-suspicious-browser-child-process]

Identifies the execution of a suspicious browser child process. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user’s web browser is typically targeted for exploitation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objective-see.com/blog/blog_0x43.html](https://objective-see.com/blog/blog_0x43.md)
* [https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang](https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4569]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Browser Child Process**

Web browsers are integral to user interaction with the internet, often serving as gateways for adversaries to exploit vulnerabilities. Attackers may execute malicious scripts or commands by spawning child processes from browsers, leveraging scripting languages or command-line tools. The detection rule identifies unusual child processes initiated by browsers on macOS, filtering out known benign activities to highlight potential threats, thus aiding in early threat detection and response.

**Possible investigation steps**

* Review the process command line to understand the context of the execution and identify any potentially malicious scripts or commands.
* Check the parent process name to confirm it is one of the specified browsers (e.g., Google Chrome, Safari) and verify if the browser was expected to be running at the time of the alert.
* Investigate the user account associated with the process to determine if the activity aligns with their typical behavior or if the account may have been compromised.
* Examine the network activity around the time of the alert to identify any suspicious connections or data transfers that may indicate further malicious activity.
* Look for any related alerts or logs that might provide additional context or evidence of a broader attack or compromise.
* Assess the risk and impact of the detected activity by considering the severity and risk score provided, and determine if immediate response actions are necessary.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they use shell scripts or command-line tools. Users can create exceptions for known update paths, such as those related to Microsoft AutoUpdate or Google Chrome installations, to prevent these from being flagged.
* Development or testing activities involving scripting languages like Python or shell scripts may be mistakenly identified as threats. Users should consider excluding specific development directories or command patterns that are frequently used in their workflows.
* Automated scripts or tools that interact with web browsers for legitimate purposes, such as web scraping or data collection, might be detected. Users can whitelist these processes by specifying their command-line arguments or paths to avoid false positives.
* System administration tasks that involve remote management or configuration changes via command-line tools could be misinterpreted as suspicious. Users should identify and exclude these routine administrative commands to reduce unnecessary alerts.
* Browser extensions or plugins that execute scripts for enhanced functionality might trigger the rule. Users should review and whitelist trusted extensions that are known to execute benign scripts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further malicious activity or lateral movement by the adversary.
* Terminate the suspicious child process identified in the alert to halt any ongoing malicious execution.
* Conduct a thorough review of the browser’s recent activity and history to identify any potentially malicious websites or downloads that may have triggered the alert.
* Remove any malicious files or scripts that were executed by the suspicious child process to prevent further exploitation.
* Apply the latest security patches and updates to the affected browser and macOS system to mitigate known vulnerabilities that could be exploited.
* Monitor the system for any signs of persistence mechanisms or additional suspicious activity, ensuring that no backdoors or unauthorized access points remain.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected, ensuring a coordinated response.


## Setup [_setup_1401]

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


## Rule query [_rule_query_5561]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.parent.name : ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh") and
  process.command_line != null and
  not process.command_line : "*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*" and
  not process.args :
    (
      "hw.model",
      "IOPlatformExpertDevice",
      "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh",
      "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/*/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
      "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container",
      "--defaults-torrc",
      "*Chrome.app",
      "Framework.framework/Versions/*/Resources/keystone_promote_preflight.sh",
      "/Users/*/Library/Application Support/Google/Chrome/recovery/*/ChromeRecovery",
      "$DISPLAY",
      "*GIO_LAUNCHED_DESKTOP_FILE_PID=$$*",
      "/opt/homebrew/*",
      "/usr/local/*brew*"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Exploitation for Client Execution
    * ID: T1203
    * Reference URL: [https://attack.mitre.org/techniques/T1203/](https://attack.mitre.org/techniques/T1203/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Drive-by Compromise
    * ID: T1189
    * Reference URL: [https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)



