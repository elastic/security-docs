---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/sublime-plugin-or-application-script-modification.html
---

# Sublime Plugin or Application Script Modification [sublime-plugin-or-application-script-modification]

Adversaries may create or modify the Sublime application plugins or scripts to execute a malicious payload each time the Sublime application is started.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5](https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_955]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sublime Plugin or Application Script Modification**

Sublime Text, a popular text editor, supports plugins and scripts written in Python to enhance functionality. Adversaries may exploit this by altering these scripts to execute malicious code whenever the application launches, achieving persistence. The detection rule identifies suspicious modifications or creations of Python files in specific Sublime directories on macOS, excluding legitimate processes, to flag potential threats.

**Possible investigation steps**

* Review the file path and name of the modified or created Python file to determine if it aligns with known Sublime Text plugin directories, specifically checking paths like "/Users/**/Library/Application Support/Sublime Text**/Packages/*.py" and "/Applications/Sublime Text.app/Contents/MacOS/sublime.py".
* Examine the process that triggered the file change or creation event, ensuring it is not one of the excluded legitimate processes such as those from "/Applications/Sublime Text*.app/Contents/**" or "/usr/local/Cellar/git/**/bin/git".
* Analyze the contents of the modified or newly created Python file for any suspicious or unauthorized code, focusing on scripts that may execute commands or connect to external networks.
* Check the modification or creation timestamp of the file to correlate with any known user activity or other security events that occurred around the same time.
* Investigate the user account associated with the file modification to determine if the activity aligns with their typical behavior or if it might indicate compromised credentials.
* Look for any additional indicators of compromise on the host, such as unusual network connections or other file modifications, to assess the broader impact of the potential threat.

**False positive analysis**

* Legitimate Sublime Text updates or installations may trigger the rule by modifying or creating Python files in the specified directories. Users can mitigate this by temporarily disabling the rule during known update periods or by verifying the update source.
* Development activities involving Sublime Text plugins or scripts can cause false positives. Developers should consider excluding their specific user paths or processes from the rule to prevent unnecessary alerts.
* Automated backup or synchronization tools that modify Sublime Text configuration files might be flagged. Users can exclude these tools' processes from the rule to avoid false positives.
* System maintenance or cleanup scripts that interact with Sublime Text directories could trigger alerts. Identifying and excluding these scripts from the rule can help manage false positives.
* Version control operations, such as those involving git, may modify files in the monitored directories. Users should ensure that legitimate git processes are included in the exclusion list to prevent false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of any potential malicious activity.
* Terminate any suspicious processes related to Sublime Text that are not part of the legitimate process list provided in the detection rule.
* Restore the modified or newly created Python files in the specified Sublime directories from a known good backup to ensure no malicious code persists.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection tools to identify and remove any additional malicious payloads.
* Review system logs and the history of file changes to identify any unauthorized access or modifications, and document findings for further analysis.
* Escalate the incident to the security operations team for a deeper investigation into potential compromise vectors and to assess the need for broader organizational response.
* Implement additional monitoring on the affected system and similar environments to detect any recurrence of the threat, ensuring enhanced logging for the specified directories and processes.


## Setup [_setup_606]

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


## Rule query [_rule_query_1003]

```js
file where host.os.type == "macos" and event.type in ("change", "creation") and file.extension : "py" and
  file.path :
    (
      "/Users/*/Library/Application Support/Sublime Text*/Packages/*.py",
      "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
    ) and
  not process.executable :
    (
      "/Applications/Sublime Text*.app/Contents/*",
      "/usr/local/Cellar/git/*/bin/git",
      "/Library/Developer/CommandLineTools/usr/bin/git",
      "/usr/libexec/xpcproxy",
      "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Host Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



