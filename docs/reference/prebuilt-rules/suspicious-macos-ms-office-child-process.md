---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-macos-ms-office-child-process.html
---

# Suspicious macOS MS Office Child Process [suspicious-macos-ms-office-child-process]

Identifies suspicious child processes of frequently targeted Microsoft Office applications (Word, PowerPoint, and Excel). These child processes are often launched during exploitation of Office applications or by documents with malicious macros.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.malwarebytes.com/cybercrime/2017/02/microsoft-office-macro-malware-targets-macs/](https://blog.malwarebytes.com/cybercrime/2017/02/microsoft-office-macro-malware-targets-macs/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Initial Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1051]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious macOS MS Office Child Process**

Microsoft Office applications on macOS can be exploited by adversaries to execute malicious child processes, often through malicious macros or document exploits. These child processes may include scripting languages or utilities that can be leveraged for unauthorized actions. The detection rule identifies such suspicious activity by monitoring for unexpected child processes spawned by Office apps, while filtering out known benign behaviors and false positives, thus helping to pinpoint potential threats.

**Possible investigation steps**

* Review the parent process name and executable path to confirm if the Office application is legitimate and expected on the host.
* Examine the child process name and command line arguments to identify any potentially malicious or unexpected behavior, such as the use of scripting languages or network utilities like curl or nscurl.
* Check the process arguments for any indicators of compromise or suspicious patterns that are not filtered out by the rule, such as unexpected network connections or file modifications.
* Investigate the effective parent executable path to ensure it is not associated with known benign applications or services that are excluded by the rule.
* Correlate the alert with any recent phishing attempts or suspicious email activity that might have led to the execution of malicious macros or document exploits.
* Analyze the host’s recent activity and system logs to identify any other anomalies or related alerts that could provide additional context or evidence of compromise.

**False positive analysis**

* Product version discovery commands can trigger false positives. Exclude processes with arguments like "ProductVersion" and "ProductBuildVersion" to reduce noise.
* Office error reporting may cause alerts. Exclude paths related to Microsoft Error Reporting to prevent unnecessary alerts.
* Network setup and management tools such as "/usr/sbin/networksetup" can be benign. Exclude these executables if they are part of regular system operations.
* Third-party applications like ToDesk and JumpCloud Agent might be flagged. Exclude their executables if they are verified as safe and part of normal operations.
* Zotero integration can cause false positives with shell processes. Exclude specific command lines involving "CFFIXED_USER_HOME/.zoteroIntegrationPipe" to avoid these alerts.

**Response and remediation**

* Immediately isolate the affected macOS device from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious child processes identified by the alert, such as those involving scripting languages or utilities like curl, bash, or osascript.
* Conduct a thorough review of the parent Microsoft Office application and associated documents to identify and remove any malicious macros or document exploits.
* Restore the affected system from a known good backup if malicious activity has compromised system integrity or data.
* Update all Microsoft Office applications to the latest version to patch any known vulnerabilities that could be exploited by similar threats.
* Implement application whitelisting to restrict the execution of unauthorized scripts and utilities, reducing the risk of exploitation through Office applications.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_660]

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


## Rule query [_rule_query_1101]

```js
process where event.action == "exec" and host.os.type == "macos" and
    process.parent.name: (
      "Microsoft Word",
      "Microsoft Outlook",
      "Microsoft Excel",
      "Microsoft PowerPoint",
      "Microsoft OneNote"
    ) and
  process.name : (
    "curl",
    "nscurl",
    "bash",
    "sh",
    "osascript",
    "python*",
    "perl*",
    "mktemp",
    "chmod",
    "php",
    "nohup",
    "openssl",
    "plutil",
    "PlistBuddy",
    "xattr",
    "mktemp",
    "sqlite3",
    "funzip",
    "popen"
  ) and

  // Filter FPs related to product version discovery and Office error reporting behavior
  not process.args:
    (
      "ProductVersion",
      "hw.model",
      "ioreg",
      "ProductName",
      "ProductUserVisibleVersion",
      "ProductBuildVersion",
      "/Library/Application Support/Microsoft/MERP*/Microsoft Error Reporting.app/Contents/MacOS/Microsoft Error Reporting",
      "open -a Safari *",
      "defaults read *",
      "sysctl hw.model*",
      "ioreg -d2 -c IOPlatformExpertDevice *",
      "ps aux | grep 'ToDesk_Desktop' | grep -v grep",
      "PIPE=\"$CFFIXED_USER_HOME/.zoteroIntegrationPipe*"
    ) and

   not process.parent.executable :
        (
          "/Applications/ToDesk.app/Contents/MacOS/ToDesk_Service",
          "/usr/local/Privacy-i/PISupervisor",
          "/Library/Addigy/lan-cache",
          "/Library/Elastic/Agent/*",
          "/opt/jc/bin/jumpcloud-agent",
          "/usr/sbin/networksetup"
        ) and
   not (process.name : "sh" and process.command_line : "*$CFFIXED_USER_HOME/.zoteroIntegrationPipe*") and

   not process.Ext.effective_parent.executable : (
        "/Applications/ToDesk.app/Contents/MacOS/ToDesk_Service",
        "/usr/local/Privacy-i/PISupervisor",
        "/Library/Addigy/auditor",
        "/Library/Elastic/Agent/*",
        "/opt/jc/bin/jumpcloud-agent",
        "/usr/sbin/networksetup"
      )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



