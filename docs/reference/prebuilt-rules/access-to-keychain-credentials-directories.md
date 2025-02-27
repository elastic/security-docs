---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/access-to-keychain-credentials-directories.html
---

# Access to Keychain Credentials Directories [access-to-keychain-credentials-directories]

Adversaries may collect the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes and certificates.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objective-see.com/blog/blog_0x25.html](https://objective-see.com/blog/blog_0x25.md)
* [https://securelist.com/calisto-trojan-for-macos/86543/](https://securelist.com/calisto-trojan-for-macos/86543/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_114]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Access to Keychain Credentials Directories**

macOS keychains securely store user credentials, such as passwords and certificates, essential for system and application authentication. Adversaries may target these directories to extract sensitive information, potentially compromising user accounts and system integrity. The detection rule identifies suspicious access attempts by monitoring process activities related to keychain directories, excluding known legitimate processes and actions, thus highlighting potential unauthorized access attempts.

**Possible investigation steps**

* Review the process details that triggered the alert, focusing on the process.args field to identify the specific keychain directory accessed and the nature of the access attempt.
* Examine the process.parent.executable and process.executable fields to determine the origin of the process and assess whether it is a known or potentially malicious application.
* Investigate the process.Ext.effective_parent.executable field to trace the parent process chain and identify any unusual or unauthorized parent processes that may have initiated the access.
* Check for any recent changes or installations on the system that could explain the access attempt, such as new software or updates that might interact with keychain directories.
* Correlate the alert with other security events or logs from the same host to identify any patterns or additional suspicious activities that could indicate a broader compromise.

**False positive analysis**

* Processes related to legitimate security applications like Microsoft Defender, JumpCloud Agent, and Rapid7 IR Agent may trigger false positives. Users can mitigate this by ensuring these applications are included in the exclusion list for process executables and effective parent executables.
* Routine administrative tasks involving keychain management, such as setting keychain settings or importing certificates, might be flagged. To handle this, users should add these specific actions to the exclusion list for process arguments.
* Applications like OpenVPN Connect and JAMF management tools that interact with keychain directories for legitimate purposes can cause false alerts. Users should verify these applications are part of the exclusion list for parent executables to prevent unnecessary alerts.
* Regular system maintenance or updates that involve keychain access might be misinterpreted as suspicious. Users should monitor these activities and adjust the exclusion criteria as needed to accommodate known maintenance processes.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule that are attempting to access keychain directories without legitimate reasons.
* Conduct a thorough review of the system’s keychain access logs to identify any unauthorized access or modifications to keychain files.
* Change all passwords and credentials stored in the keychain on the affected system to prevent potential misuse of compromised credentials.
* Restore the system from a known good backup if unauthorized access has led to system integrity issues or data corruption.
* Implement additional monitoring on the affected system to detect any further unauthorized access attempts, focusing on the keychain directories and related processes.
* Escalate the incident to the security operations team for further investigation and to determine if the threat is part of a larger attack campaign.


## Setup [_setup_63]

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


## Rule query [_rule_query_118]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Keychains/*",
      "/Library/Keychains/*",
      "/Network/Library/Keychains/*",
      "System.keychain",
      "login.keychain-db",
      "login.keychain"
    ) and
    not process.args : ("find-certificate",
                        "add-trusted-cert",
                        "set-keychain-settings",
                        "delete-certificate",
                        "/Users/*/Library/Keychains/openvpn.keychain-db",
                        "show-keychain-info",
                        "lock-keychain",
                        "set-key-partition-list",
                        "import",
                        "find-identity") and
    not process.parent.executable :
      (
        "/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect",
        "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon_enterprise.app/Contents/MacOS/wdavdaemon_enterprise",
        "/opt/jc/bin/jumpcloud-agent"
      ) and
    not process.executable : ("/opt/jc/bin/jumpcloud-agent", "/usr/bin/basename") and
    not process.Ext.effective_parent.executable : ("/opt/rapid7/ir_agent/ir_agent",
                                                   "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint",
                                                   "/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cloud-agent",
                                                   "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                   "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService",
                                                   "/usr/local/jamf/bin/jamf",
                                                   "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Keychain
    * ID: T1555.001
    * Reference URL: [https://attack.mitre.org/techniques/T1555/001/](https://attack.mitre.org/techniques/T1555/001/)



