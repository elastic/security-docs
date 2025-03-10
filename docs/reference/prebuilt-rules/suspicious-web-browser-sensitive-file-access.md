---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-web-browser-sensitive-file-access.html
---

# Suspicious Web Browser Sensitive File Access [suspicious-web-browser-sensitive-file-access]

Identifies the access or file open of web browser sensitive files by an untrusted/unsigned process or osascript. Adversaries may acquire credentials from web browsers by reading files specific to the target browser.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://securelist.com/calisto-trojan-for-macos/86543/](https://securelist.com/calisto-trojan-for-macos/86543/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1043]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Web Browser Sensitive File Access**

Web browsers store sensitive data like cookies and login credentials in specific files. Adversaries exploit this by accessing these files using untrusted or unsigned processes, potentially stealing credentials. The detection rule identifies such unauthorized access on macOS by monitoring file access events, focusing on untrusted processes or scripts, and excluding known safe executables, thus flagging potential credential theft attempts.

**Possible investigation steps**

* Review the process executable path and name to determine if it is a known legitimate application or script, focusing on those not signed by trusted entities or identified as osascript.
* Check the process code signature details to verify if the process is unsigned or untrusted, which could indicate malicious activity.
* Investigate the user account associated with the process to determine if there is any unusual or unauthorized activity, such as unexpected logins or privilege escalations.
* Examine the file access event details, including the specific sensitive file accessed (e.g., cookies.sqlite, logins.json), to assess the potential impact on credential security.
* Correlate the event with other security alerts or logs from the same host or user to identify any patterns or additional suspicious activities that might indicate a broader compromise.
* Verify if the process executable path matches any known safe paths, such as the excluded path for the Elastic Endpoint, to rule out false positives.

**False positive analysis**

* Access by legitimate applications: Some legitimate applications may access browser files for valid reasons, such as backup or synchronization tools. Users can create exceptions for these applications by adding their code signatures to the exclusion list.
* Developer or testing scripts: Developers might use scripts like osascript for testing purposes, which could trigger the rule. To manage this, users can whitelist specific scripts or processes used in development environments.
* Security software interactions: Security tools might access browser files as part of their scanning or monitoring activities. Users should verify the legitimacy of these tools and add them to the exclusion list if they are trusted.
* System maintenance tasks: Automated system maintenance tasks might access browser files. Users can identify these tasks and exclude them if they are part of routine system operations and deemed safe.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any untrusted or unsigned processes identified in the alert, especially those accessing sensitive browser files.
* Conduct a thorough review of the affected system’s recent activity logs to identify any additional suspicious behavior or potential lateral movement.
* Change all potentially compromised credentials, focusing on those stored in the affected web browsers, and enforce multi-factor authentication where possible.
* Restore any altered or deleted sensitive files from a known good backup to ensure data integrity.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Update endpoint protection and monitoring tools to enhance detection capabilities for similar unauthorized access attempts in the future.


## Setup [_setup_656]

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


## Rule query [_rule_query_1096]

```js
file where event.action == "open" and host.os.type == "macos" and process.executable != null and
 file.name : ("cookies.sqlite",
              "key?.db",
              "logins.json",
              "Cookies",
              "Cookies.binarycookies",
              "Login Data") and
 ((process.code_signature.trusted == false or process.code_signature.exists == false) or process.name : "osascript") and
 not process.code_signature.signing_id : "org.mozilla.firefox" and
 not Effective_process.executable : "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Web Session Cookie
    * ID: T1539
    * Reference URL: [https://attack.mitre.org/techniques/T1539/](https://attack.mitre.org/techniques/T1539/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Credentials from Web Browsers
    * ID: T1555.003
    * Reference URL: [https://attack.mitre.org/techniques/T1555/003/](https://attack.mitre.org/techniques/T1555/003/)



