---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-calendar-file-modification.html
---

# Suspicious Calendar File Modification [prebuilt-rule-8-17-4-suspicious-calendar-file-modification]

Identifies suspicious modifications of the calendar file by an unusual process. Adversaries may create a custom calendar notification procedure to execute a malicious program at a recurring interval to establish persistence.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos](https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos)
* [https://github.com/FSecureLABS/CalendarPersist](https://github.com/FSecureLABS/CalendarPersist)
* [https://github.com/D00MFist/PersistentJXA/blob/master/CalendarPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/CalendarPersist.js)

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

## Investigation guide [_investigation_guide_4600]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Calendar File Modification**

Calendar files on macOS can be manipulated to trigger events, potentially allowing adversaries to execute malicious programs at set intervals, thus achieving persistence. This detection rule identifies unusual processes modifying calendar files, excluding known legitimate applications. By focusing on unexpected executables altering these files, it helps uncover potential threats exploiting calendar notifications for malicious purposes.

**Possible investigation steps**

* Review the process executable path that triggered the alert to determine if it is a known or unknown application, focusing on paths not excluded by the rule.
* Examine the modification timestamp of the calendar file to correlate with any known user activity or scheduled tasks that might explain the change.
* Check the user account associated with the file modification to assess if the activity aligns with typical user behavior or if it suggests unauthorized access.
* Investigate any recent installations or updates of applications on the system that might have introduced new or unexpected executables.
* Look for additional indicators of compromise on the host, such as unusual network connections or other file modifications, to assess if the calendar file change is part of a broader attack.

**False positive analysis**

* Legitimate third-party calendar applications may modify calendar files as part of their normal operation. Users can create exceptions for these known applications by adding their executable paths to the exclusion list.
* Automated backup or synchronization tools might access and modify calendar files. Identify these tools and exclude their processes to prevent false alerts.
* User scripts or automation workflows that interact with calendar files for personal productivity purposes can trigger this rule. Review and whitelist these scripts if they are verified as non-malicious.
* System updates or maintenance tasks occasionally modify calendar files. Monitor the timing of such events and correlate them with known update schedules to differentiate between legitimate and suspicious activities.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or further execution of malicious programs.
* Terminate any suspicious processes identified as modifying calendar files that are not part of the known legitimate applications list.
* Restore the calendar files from a known good backup to ensure no malicious events are scheduled.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious software.
* Review and audit user accounts and permissions on the affected system to ensure no unauthorized access or privilege escalation has occurred.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems may be affected.
* Implement additional monitoring and alerting for unusual calendar file modifications across the network to enhance detection of similar threats in the future.


## Setup [_setup_1432]

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


## Rule query [_rule_query_5592]

```js
event.category:file and host.os.type:macos and event.action:modification and
  file.path:/Users/*/Library/Calendars/*.calendar/Events/*.ics and
  process.executable:
  (* and not
    (
      /System/Library/* or
      /System/Applications/Calendar.app/Contents/MacOS/* or
      /System/Applications/Mail.app/Contents/MacOS/Mail or
      /usr/libexec/xpcproxy or
      /sbin/launchd or
      /Applications/*
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)



