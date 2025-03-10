---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/keychain-password-retrieval-via-command-line.html
---

# Keychain Password Retrieval via Command Line [keychain-password-retrieval-via-command-line]

Adversaries may collect keychain storage data from a system to in order to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features, including Wi-Fi and website passwords, secure notes, certificates, and Kerberos.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.netmeister.org/blog/keychain-passwords.html](https://www.netmeister.org/blog/keychain-passwords.md)
* [https://github.com/priyankchheda/chrome_password_grabber/blob/master/chrome.py](https://github.com/priyankchheda/chrome_password_grabber/blob/master/chrome.py)
* [https://ss64.com/osx/security.html](https://ss64.com/osx/security.md)
* [https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/](https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_453]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Keychain Password Retrieval via Command Line**

Keychain is macOS’s secure storage system for managing user credentials, including passwords and certificates. Adversaries may exploit command-line tools to extract sensitive data from Keychain, targeting browsers like Chrome and Safari. The detection rule identifies suspicious command executions involving Keychain access, focusing on specific arguments and excluding legitimate applications, to flag potential credential theft attempts.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the *security* command with arguments *-wa* or *-ga* and *find-generic-password* or *find-internet-password*, as these indicate attempts to access Keychain data.
* Examine the command line for references to browsers such as Chrome, Safari, or others specified in the rule to determine if the target was browser-related credentials.
* Investigate the parent process of the suspicious command to ensure it is not a legitimate application, specifically checking that it is not the Keeper Password Manager, as this is excluded in the rule.
* Check the user account associated with the process execution to determine if the activity aligns with expected behavior for that user or if it suggests unauthorized access.
* Review recent login and access logs for the system to identify any unusual or unauthorized access patterns that could correlate with the suspicious Keychain access attempt.
* Assess the system for any additional indicators of compromise or related suspicious activities that might suggest a broader security incident.

**False positive analysis**

* Legitimate password managers like Keeper Password Manager may trigger the rule due to their access to Keychain for managing user credentials. To handle this, ensure that the process parent executable path for such applications is added to the exclusion list.
* System maintenance or administrative scripts that access Keychain for legitimate purposes might be flagged. Review these scripts and, if verified as safe, add their specific command patterns to the exception list.
* Development or testing tools that interact with browsers and require Keychain access could cause false positives. Identify these tools and exclude their specific process names or command-line arguments if they are part of regular operations.
* Automated backup or synchronization services that access browser credentials stored in Keychain may be mistakenly identified. Confirm these services' legitimacy and exclude their associated processes from the detection rule.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, particularly those involving the *security* command with the specified arguments targeting browsers.
* Conduct a thorough review of the system’s keychain access logs to identify any unauthorized access attempts and determine the scope of the compromise.
* Change all potentially compromised credentials stored in the keychain, including browser passwords and Wi-Fi credentials, and ensure they are updated across all relevant services.
* Implement additional monitoring on the affected system and similar endpoints to detect any further attempts to access keychain data using command-line tools.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.
* Review and update endpoint security configurations to restrict unauthorized access to keychain data and enhance logging for keychain-related activities.


## Setup [_setup_289]

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


## Rule query [_rule_query_488]

```js
process where host.os.type == "macos" and event.action == "exec" and
 process.name : "security" and
 process.args : ("-wa", "-ga") and process.args : ("find-generic-password", "find-internet-password") and
 process.command_line : ("*Chrome*", "*Chromium*", "*Opera*", "*Safari*", "*Brave*", "*Microsoft Edge*", "*Firefox*") and
 not process.parent.executable : "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
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

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Credentials from Web Browsers
    * ID: T1555.003
    * Reference URL: [https://attack.mitre.org/techniques/T1555/003/](https://attack.mitre.org/techniques/T1555/003/)



