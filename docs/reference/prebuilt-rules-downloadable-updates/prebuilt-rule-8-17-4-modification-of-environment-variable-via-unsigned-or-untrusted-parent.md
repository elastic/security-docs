---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-modification-of-environment-variable-via-unsigned-or-untrusted-parent.html
---

# Modification of Environment Variable via Unsigned or Untrusted Parent [prebuilt-rule-8-17-4-modification-of-environment-variable-via-unsigned-or-untrusted-parent]

Identifies modifications to an environment variable using the built-in launchctl command. Adversaries may execute their own malicious payloads by hijacking certain environment variables to load arbitrary libraries or bypass certain restrictions.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/rapid7/metasploit-framework/blob/master//modules/post/osx/escalate/tccbypass.rb](https://github.com/rapid7/metasploit-framework/blob/master//modules/post/osx/escalate/tccbypass.rb)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4560]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification of Environment Variable via Unsigned or Untrusted Parent**

Environment variables in macOS are crucial for configuring system and application behavior. Adversaries may exploit these by using the `launchctl` command to alter variables, enabling malicious payload execution or bypassing restrictions. The detection rule identifies suspicious modifications initiated by untrusted or unsigned parent processes, focusing on atypical environment variables and excluding known safe executables, thus highlighting potential threats.

**Possible investigation steps**

* Review the process tree to identify the parent process of the `launchctl` command, focusing on whether the parent process is unsigned or untrusted, as indicated by the absence or lack of trust in the `process.parent.code_signature`.
* Examine the command-line arguments used with `launchctl`, specifically looking for the `setenv` command and any unusual or suspicious environment variables that are not part of the known safe list (e.g., ANT_HOME, DBUS_LAUNCHD_SESSION_BUS_SOCKET).
* Check the execution path of the parent process to determine if it matches any known safe executables, such as those listed in the exclusion criteria (e.g., /Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/lib/jspawnhelper).
* Investigate the user account under which the `launchctl` command was executed to determine if it aligns with expected behavior or if it might indicate a compromised account.
* Correlate this event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise that might suggest a broader attack or intrusion attempt.

**False positive analysis**

* Development tools like IntelliJ IDEA may trigger false positives when using the jspawnhelper executable. To mitigate this, add the executable path to the exclusion list if it is a known and trusted application in your environment.
* NoMachine software can cause false positives due to its use of nxserver.bin. If this software is regularly used and trusted, consider excluding its executable path from the detection rule.
* The kr tool located at /usr/local/bin/kr might be flagged as a false positive. If this tool is part of your standard operations, ensure its path is excluded to prevent unnecessary alerts.
* Review any other unsigned or untrusted parent processes that are part of legitimate software installations or operations. If they are verified as safe, add them to the exclusion list to reduce false positives.
* Regularly update the list of known safe executables and environment variables to reflect changes in your software inventory, ensuring that legitimate processes are not mistakenly flagged.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or further exploitation.
* Terminate any suspicious processes associated with the untrusted or unsigned parent process that initiated the `launchctl` command to halt any ongoing malicious activity.
* Conduct a thorough review of the environment variables modified by the `launchctl` command to identify any unauthorized changes and revert them to their original state.
* Analyze the parent process that triggered the alert to determine its origin and purpose, and remove any malicious or unauthorized software identified during this analysis.
* Restore the system from a known good backup if any critical system components or configurations have been compromised.
* Implement additional monitoring and logging for `launchctl` usage and environment variable modifications to detect similar threats in the future.
* Escalate the incident to the security operations team for further investigation and to assess the need for broader organizational response measures.


## Setup [_setup_1392]

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


## Rule query [_rule_query_5552]

```js
event.category:process and host.os.type:macos and event.type:start and
  process.name:launchctl and
  (process.parent.code_signature.exists : false or process.parent.code_signature.trusted : false) and
  process.args:(setenv and not (ANT_HOME or
                                DBUS_LAUNCHD_SESSION_BUS_SOCKET or
                                EDEN_ENV or
                                LG_WEBOS_TV_SDK_HOME or
                                RUNTIME_JAVA_HOME or
                                WEBOS_CLI_TV or
                                JAVA*_HOME) and
                not *.vmoptions) and
  not process.parent.executable:("/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/lib/jspawnhelper" or
                                  /Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin or
                                  /Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin or
                                  /usr/local/bin/kr)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Path Interception by PATH Environment Variable
    * ID: T1574.007
    * Reference URL: [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)



