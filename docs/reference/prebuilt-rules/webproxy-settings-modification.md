---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/webproxy-settings-modification.html
---

# WebProxy Settings Modification [webproxy-settings-modification]

Identifies the use of the built-in networksetup command to configure webproxy settings. This may indicate an attempt to hijack web browser traffic for credential access via traffic sniffing or redirection.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/](https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/)
* [https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1194]

**Triage and analysis**

[TBC: QUOTE]
**Investigating WebProxy Settings Modification**

Web proxy settings in macOS manage how web traffic is routed, often used to enhance security or manage network traffic. Adversaries may exploit these settings to redirect or intercept web traffic, potentially capturing sensitive data like credentials. The detection rule identifies suspicious use of the `networksetup` command to alter proxy settings, excluding known legitimate applications, thus highlighting potential unauthorized modifications indicative of malicious activity.

**Possible investigation steps**

* Review the process details to confirm the use of the networksetup command with arguments like -setwebproxy, -setsecurewebproxy, or -setautoproxyurl, which indicate an attempt to modify web proxy settings.
* Check the parent process information to ensure it is not one of the known legitimate applications such as /Library/PrivilegedHelperTools/com.80pct.FreedomHelper or /Applications/Fiddler Everywhere.app/Contents/Resources/app/out/WebServer/Fiddler.WebUi.
* Investigate the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Examine recent network traffic logs for unusual patterns or connections that could suggest traffic redirection or interception.
* Look for any additional alerts or logs related to the same host or user that might indicate a broader pattern of suspicious activity.
* Assess the system for any signs of compromise or unauthorized access, such as unexpected user accounts or changes to system configurations.

**False positive analysis**

* Legitimate applications like FreedomHelper, Fiddler Everywhere, and xpcproxy may trigger the rule when they modify proxy settings. To prevent these from being flagged, ensure they are included in the exclusion list of known applications.
* Network management tools such as Proxyman and Incoggo might also be detected. Add these to the exclusion list to avoid unnecessary alerts.
* Regular system updates or configurations by IT administrators can sometimes involve proxy setting changes. Coordinate with IT to identify these activities and consider adding them to the exclusion criteria if they are routine and verified as safe.
* Automated scripts or maintenance tasks that adjust proxy settings for legitimate reasons should be reviewed and, if deemed non-threatening, excluded from detection to reduce false positives.
* Monitor for any new applications or processes that may need to be added to the exclusion list as part of ongoing security management to ensure the rule remains effective without generating excessive false alerts.

**Response and remediation**

* Immediately isolate the affected macOS device from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes related to the `networksetup` command that are not associated with known legitimate applications.
* Review and reset the web proxy settings on the affected device to their default or intended configuration to ensure no malicious redirection is in place.
* Conduct a thorough scan of the affected system using updated security tools to identify and remove any malware or unauthorized software that may have been installed.
* Analyze logs and network traffic to identify any data that may have been intercepted or exfiltrated, focusing on sensitive information such as credentials.
* Escalate the incident to the security operations team for further investigation and to determine if other systems may be affected.
* Implement enhanced monitoring and alerting for similar activities across the network to detect and respond to future attempts promptly.


## Setup [_setup_754]

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


## Rule query [_rule_query_1220]

```js
event.category:process and host.os.type:macos and event.type:start and
 process.name : networksetup and process.args : (("-setwebproxy" or "-setsecurewebproxy" or "-setautoproxyurl") and not (Bluetooth or off)) and
 not process.parent.executable : ("/Library/PrivilegedHelperTools/com.80pct.FreedomHelper" or
                                  "/Applications/Fiddler Everywhere.app/Contents/Resources/app/out/WebServer/Fiddler.WebUi" or
                                  "/usr/libexec/xpcproxy") and
 not process.Ext.effective_parent.executable : ("/Applications/Proxyman.app/Contents/MacOS/Proxyman" or "/Applications/Incoggo.app/Contents/MacOS/Incoggo.app")
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



