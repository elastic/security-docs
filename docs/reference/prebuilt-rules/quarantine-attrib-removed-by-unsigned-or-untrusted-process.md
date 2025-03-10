---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/quarantine-attrib-removed-by-unsigned-or-untrusted-process.html
---

# Quarantine Attrib Removed by Unsigned or Untrusted Process [quarantine-attrib-removed-by-unsigned-or-untrusted-process]

Detects deletion of the quarantine attribute by an unusual process (xattr). In macOS, when applications or programs are downloaded from the internet, there is a quarantine flag set on the file. This attribute is read by Apple’s Gatekeeper defense program at execution time. An adversary may disable this attribute to evade defenses.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://nixhacker.com/security-protection-in-macos-1/](https://nixhacker.com/security-protection-in-macos-1/)
* [https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/](https://eclecticlight.co/2020/10/29/quarantine-and-the-quarantine-flag/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 110

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_846]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Quarantine Attrib Removed by Unsigned or Untrusted Process**

In macOS, files downloaded from the internet are tagged with a quarantine attribute, which is checked by Gatekeeper to ensure safety before execution. Adversaries may remove this attribute to bypass security checks, allowing potentially harmful applications to run unchecked. The detection rule identifies such actions by monitoring for the removal of this attribute by processes that are either unsigned or untrusted, flagging unusual activity that deviates from expected behavior.

**Possible investigation steps**

* Review the process executable path that triggered the alert to determine if it is a known or expected application on the system. Check if it matches any legitimate software that might not be properly signed.
* Investigate the parent process of the flagged executable to understand the context of its execution. This can help identify if the process was spawned by a legitimate application or a potentially malicious one.
* Examine the file path from which the quarantine attribute was removed to assess if it is a common location for downloaded files or if it appears suspicious.
* Check the system for any recent downloads or installations that might correlate with the time of the alert to identify potential sources of the file.
* Look into the user account under which the process was executed to determine if it aligns with expected user behavior or if it might indicate unauthorized access.
* Search for any other alerts or logs related to the same process or file path to identify patterns or repeated attempts to bypass security measures.

**False positive analysis**

* System processes or legitimate applications may occasionally remove the quarantine attribute as part of their normal operation. Users can create exceptions for known safe processes by adding them to the exclusion list in the detection rule.
* Software updates or installations from trusted vendors might trigger the rule if they are not properly signed. Verify the legitimacy of the software and consider adding the specific executable path to the exclusion list if it is deemed safe.
* Custom scripts or automation tools used within an organization might remove the quarantine attribute as part of their workflow. Review these scripts to ensure they are secure and add their paths to the exclusion list to prevent false positives.
* Temporary files or directories, such as those in /private/var/folders, are already excluded to reduce noise. Ensure that any additional temporary paths used by trusted applications are similarly excluded if they are known to cause false positives.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or further compromise.
* Terminate any untrusted or unsigned processes identified in the alert that are responsible for removing the quarantine attribute.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious software.
* Restore any affected files from a known good backup if they have been altered or compromised.
* Review system logs and the specific file paths involved in the alert to identify any additional unauthorized changes or suspicious activity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring and alerting for similar activities on other macOS systems to enhance detection and response capabilities.


## Setup [_setup_553]

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


## Rule query [_rule_query_903]

```js
file where event.action == "extended_attributes_delete" and host.os.type == "macos" and process.executable != null and
(process.code_signature.trusted == false or process.code_signature.exists == false) and not
process.executable : ("/usr/bin/xattr",
                      "/System/*",
                      "/private/tmp/KSInstallAction.*/*/Install Google Software Update.app/Contents/Helpers/ksinstall",
                      "/Applications/CEWE Fotoschau.app/Contents/MacOS/FotoPlus",
                      "/Applications/.com.bomgar.scc.*/Remote Support Customer Client.app/Contents/MacOS/sdcust") and not
file.path : "/private/var/folders/*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



