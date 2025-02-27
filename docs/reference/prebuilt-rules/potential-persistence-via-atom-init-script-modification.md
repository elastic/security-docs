---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-persistence-via-atom-init-script-modification.html
---

# Potential Persistence via Atom Init Script Modification [potential-persistence-via-atom-init-script-modification]

Identifies modifications to the Atom desktop text editor Init File. Adversaries may add malicious JavaScript code to the init.coffee file that will be executed upon the Atom application opening.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/D00MFist/PersistentJXA/blob/master/AtomPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/AtomPersist.js)
* [https://flight-manual.atom.io/hacking-atom/sections/the-init-file/](https://flight-manual.atom.io/hacking-atom/sections/the-init-file/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_720]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Persistence via Atom Init Script Modification**

Atom, a popular text editor, allows customization via the `init.coffee` script, which executes JavaScript upon startup. Adversaries exploit this by embedding malicious code, ensuring persistence each time Atom launches. The detection rule identifies suspicious modifications to this script on macOS, excluding benign processes and root user actions, thus highlighting potential unauthorized persistence attempts.

**Possible investigation steps**

* Review the file modification details for /Users/*/.atom/init.coffee to identify the exact changes made to the script.
* Investigate the process that modified the init.coffee file by examining the process name and user associated with the modification, ensuring it is not Atom, xpcproxy, or the root user.
* Check the user account involved in the modification for any unusual activity or recent changes, such as new software installations or privilege escalations.
* Analyze the content of the modified init.coffee file for any suspicious or unfamiliar JavaScript code that could indicate malicious intent.
* Correlate the modification event with other security alerts or logs from the same host to identify any related suspicious activities or patterns.
* If malicious code is found, isolate the affected system and conduct a deeper forensic analysis to determine the scope and impact of the potential compromise.

**False positive analysis**

* Frequent legitimate updates to the init.coffee file by developers or power users can trigger alerts. To manage this, create exceptions for specific user accounts known to regularly modify this file for legitimate purposes.
* Automated scripts or tools that modify the init.coffee file as part of a legitimate configuration management process may cause false positives. Identify these processes and exclude them from the rule by adding their process names to the exception list.
* Non-malicious third-party Atom packages that require modifications to the init.coffee file for functionality can be mistaken for threats. Review and whitelist these packages if they are verified as safe and necessary for user workflows.
* System maintenance or administrative tasks performed by non-root users that involve changes to the init.coffee file might be flagged. Consider adding exceptions for these specific maintenance activities if they are routine and verified as non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious code.
* Review the contents of the `init.coffee` file to identify and document any unauthorized or suspicious code modifications.
* Remove any malicious code found in the `init.coffee` file and restore it to a known good state, either by reverting to a backup or by manually cleaning the file.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or persistence mechanisms.
* Change the credentials of the user account associated with the modified `init.coffee` file to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems may be affected.
* Implement monitoring for future unauthorized changes to the `init.coffee` file and similar persistence mechanisms, enhancing detection capabilities to quickly identify and respond to similar threats.


## Setup [_setup_457]

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


## Rule query [_rule_query_767]

```js
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)



