---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-child-process-of-adobe-acrobat-reader-update-service.html
---

# Suspicious Child Process of Adobe Acrobat Reader Update Service [prebuilt-rule-8-17-4-suspicious-child-process-of-adobe-acrobat-reader-update-service]

Detects attempts to exploit privilege escalation vulnerabilities related to the Adobe Acrobat Reader PrivilegedHelperTool responsible for installing updates. For more information, refer to CVE-2020-9615, CVE-2020-9614 and CVE-2020-9613 and verify that the impacted system is patched.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://rekken.github.io/2020/05/14/Security-Flaws-in-Adobe-Acrobat-Reader-Allow-Malicious-Program-to-Gain-Root-on-macOS-Silently/](https://rekken.github.io/2020/05/14/Security-Flaws-in-Adobe-Acrobat-Reader-Allow-Malicious-Program-to-Gain-Root-on-macOS-Silently/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4604]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Child Process of Adobe Acrobat Reader Update Service**

Adobe Acrobat Reader’s update service on macOS uses a privileged helper tool to manage updates, running with elevated permissions. Adversaries may exploit vulnerabilities in this service to escalate privileges by spawning unauthorized child processes. The detection rule identifies such anomalies by monitoring for unexpected child processes initiated by the update service, especially those not matching known legitimate executables, thus flagging potential exploitation attempts.

**Possible investigation steps**

* Review the alert details to confirm the parent process is com.adobe.ARMDC.SMJobBlessHelper and the user is root, as these are key indicators of potential exploitation.
* Identify the child process executable that triggered the alert and determine if it is known or expected in the context of Adobe Acrobat Reader updates.
* Check the system for any recent updates or patches related to Adobe Acrobat Reader to ensure they are up to date, particularly concerning CVE-2020-9615, CVE-2020-9614, and CVE-2020-9613.
* Investigate the process tree to understand the sequence of events leading to the suspicious child process, looking for any unusual or unauthorized activities.
* Examine system logs and other security tools for additional indicators of compromise or related suspicious activities around the time of the alert.
* Assess the system for any signs of privilege escalation or unauthorized access, focusing on changes made by the suspicious process.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they spawn child processes not listed in the known legitimate executables. Users can mitigate this by monitoring update schedules and temporarily excluding these processes during known update windows.
* Custom scripts or administrative tools executed by system administrators with root privileges might be flagged. To handle this, users can create exceptions for these specific scripts or tools if they are verified as safe and necessary for operations.
* Security or system management tools that perform integrity checks or system modifications could be misidentified as suspicious. Users should review these tools and, if deemed safe, add them to the exclusion list to prevent false alerts.
* Development or testing environments where new or experimental software is frequently run may generate false positives. In such cases, users can establish a separate monitoring profile with adjusted rules to accommodate the unique activities of these environments.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious child processes identified by the detection rule that do not match known legitimate executables, ensuring that no unauthorized processes are running.
* Conduct a thorough review of system logs and process execution history to identify any additional indicators of compromise or unauthorized changes made by the suspicious process.
* Apply the latest security patches and updates to Adobe Acrobat Reader and the macOS system to address vulnerabilities CVE-2020-9615, CVE-2020-9614, and CVE-2020-9613, ensuring the system is not susceptible to known exploits.
* Restore any affected files or system configurations from a known good backup to ensure system integrity and remove any potential backdoors or malicious modifications.
* Enhance monitoring and logging on the affected system to detect any future unauthorized process executions or privilege escalation attempts, ensuring quick detection and response.
* Report the incident to the appropriate internal security team or external authorities if required, providing detailed information about the threat and actions taken for further investigation and compliance.


## Setup [_setup_1436]

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


## Rule query [_rule_query_5596]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.parent.name:com.adobe.ARMDC.SMJobBlessHelper and
  user.name:root and
  not process.executable: (/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper or
                           /usr/bin/codesign or
                           /private/var/folders/zz/*/T/download/ARMDCHammer or
                           /usr/sbin/pkgutil or
                           /usr/bin/shasum or
                           /usr/bin/perl* or
                           /usr/sbin/spctl or
                           /usr/sbin/installer or
                           /usr/bin/csrutil)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



