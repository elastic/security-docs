---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-hidden-local-user-account-creation.html
---

# Potential Hidden Local User Account Creation [prebuilt-rule-8-17-4-potential-hidden-local-user-account-creation]

Identifies attempts to create a local account that will be hidden from the macOS logon window. This may indicate an attempt to evade user attention while maintaining persistence using a separate local account.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.apple.com/en-us/HT203998](https://support.apple.com/en-us/HT203998)

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

## Investigation guide [_investigation_guide_4579]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Hidden Local User Account Creation**

In macOS environments, the `dscl` command-line utility manages directory services, including user accounts. Adversaries may exploit this to create hidden local accounts, evading detection while maintaining persistence. The detection rule monitors for `dscl` processes attempting to set accounts as hidden, flagging suspicious activity indicative of potential misuse.

**Possible investigation steps**

* Review the process details to confirm the presence of the `dscl` command with arguments related to account creation and hiding, specifically checking for `IsHidden`, `create`, and values like `true`, `1`, or `yes`.
* Identify the user account under which the `dscl` command was executed to determine if it was initiated by an authorized user or a potential adversary.
* Check the system logs for any additional suspicious activity around the time the `dscl` command was executed, such as other unauthorized account modifications or unusual login attempts.
* Investigate the newly created account details, if available, to assess its purpose and legitimacy, including checking for any associated files or processes that might indicate malicious intent.
* Correlate the event with other security alerts or anomalies on the host to determine if this activity is part of a broader attack pattern or isolated incident.

**False positive analysis**

* System administrators may use the dscl command to create hidden accounts for legitimate purposes such as maintenance or automated tasks. To manage this, create exceptions for known administrator accounts or scripts that regularly perform these actions.
* Some third-party applications or management tools might use hidden accounts for functionality or security purposes. Identify these applications and whitelist their processes to prevent unnecessary alerts.
* During system setup or configuration, hidden accounts might be created as part of the initial setup process. Exclude these initial setup activities by correlating them with known installation or configuration events.
* Regular audits of user accounts and their creation processes can help distinguish between legitimate and suspicious account creation activities, allowing for more informed exception handling.
* If a specific user or group frequently triggers this rule due to their role, consider creating a role-based exception to reduce noise while maintaining security oversight.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Use administrative privileges to review and remove any unauthorized hidden user accounts created using the `dscl` command. Ensure that legitimate accounts are not affected.
* Change passwords for all local accounts on the affected system to prevent unauthorized access using potentially compromised credentials.
* Conduct a thorough review of system logs and security alerts to identify any additional suspicious activities or indicators of compromise related to the hidden account creation.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement enhanced monitoring for `dscl` command usage across all macOS systems in the environment to detect and respond to similar threats promptly.
* Update and reinforce endpoint security measures, such as ensuring all systems have the latest security patches and antivirus definitions, to prevent exploitation of known vulnerabilities.


## Setup [_setup_1411]

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


## Rule query [_rule_query_5571]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:dscl and process.args:(IsHidden and create and (true or 1 or yes))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



