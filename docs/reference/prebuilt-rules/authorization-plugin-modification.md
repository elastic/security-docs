---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/authorization-plugin-modification.html
---

# Authorization Plugin Modification [authorization-plugin-modification]

Authorization plugins are used to extend the authorization services API and implement mechanisms that are not natively supported by the OS, such as multi-factor authentication with third party software. Adversaries may abuse this feature to persist and/or collect clear text credentials as they traverse the registered plugins during user logon.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/documentation/security/authorization_plug-ins](https://developer.apple.com/documentation/security/authorization_plug-ins)
* [https://www.xorrior.com/persistent-credential-theft/](https://www.xorrior.com/persistent-credential-theft/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_171]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Authorization Plugin Modification**

Authorization plugins in macOS extend authentication capabilities, enabling features like third-party multi-factor authentication. Adversaries may exploit these plugins to maintain persistence or capture credentials by modifying or adding unauthorized plugins. The detection rule identifies suspicious modifications by monitoring changes in specific plugin directories, excluding known legitimate plugins and trusted processes, thus highlighting potential unauthorized activities.

**Possible investigation steps**

* Review the file path of the modified plugin to determine if it is located in the /Library/Security/SecurityAgentPlugins/ directory and verify if it is not among the known legitimate plugins like KandjiPassport.bundle or TeamViewerAuthPlugin.bundle.
* Examine the process name associated with the modification event to ensure it is not *shove* with a trusted code signature, as these are excluded from the detection rule.
* Investigate the history of the modified plugin file to identify when it was created or last modified and by which user or process, to assess if the change aligns with expected administrative activities.
* Check for any recent user logon events that might correlate with the timing of the plugin modification to identify potential unauthorized access attempts.
* Analyze any associated network activity or connections from the host around the time of the modification to detect possible data exfiltration or communication with external command and control servers.
* Review system logs for any other suspicious activities or anomalies that occurred around the same time as the plugin modification to gather additional context on the potential threat.

**False positive analysis**

* Known legitimate plugins such as KandjiPassport.bundle and TeamViewerAuthPlugin.bundle may trigger alerts if they are updated or modified. Users can handle these by ensuring these plugins are included in the exclusion list within the detection rule.
* Trusted processes like those signed by a verified code signature, such as the process named *shove*, might be flagged if they interact with the plugin directories. Users should verify the code signature and add these processes to the trusted list to prevent false positives.
* System updates or legitimate software installations may cause temporary changes in the plugin directories. Users should monitor for these events and temporarily adjust the detection rule to exclude these known activities during the update period.
* Custom or in-house developed plugins that are not widely recognized may be flagged. Users should ensure these plugins are properly documented and added to the exclusion list if they are verified as safe and necessary for business operations.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or further unauthorized access.
* Review and terminate any suspicious processes associated with unauthorized plugins, especially those not signed by a trusted code signature.
* Remove any unauthorized or suspicious plugins from the /Library/Security/SecurityAgentPlugins/ directory to eliminate persistence mechanisms.
* Conduct a thorough credential audit for any accounts that may have been compromised, and enforce a password reset for affected users.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar endpoints to detect any further unauthorized plugin modifications.
* Review and update security policies to ensure only authorized personnel can modify or add authorization plugins, and consider implementing stricter access controls.


## Setup [_setup_108]

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


## Rule query [_rule_query_176]

```js
event.category:file and host.os.type:macos and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not (/Library/Security/SecurityAgentPlugins/KandjiPassport.bundle/* or /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/*)) and
  not (process.name:shove and process.code_signature.trusted:true)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Authentication Package
    * ID: T1547.002
    * Reference URL: [https://attack.mitre.org/techniques/T1547/002/](https://attack.mitre.org/techniques/T1547/002/)



