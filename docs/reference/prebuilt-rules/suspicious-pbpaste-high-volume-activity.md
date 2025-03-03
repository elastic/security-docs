---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-pbpaste-high-volume-activity.html
---

# Suspicious pbpaste High Volume Activity [suspicious-pbpaste-high-volume-activity]

Identifies a high volume of `pbpaste` executions, which may indicate a bash loop continuously collecting clipboard contents, potentially allowing an attacker to harvest user credentials or other sensitive information.

**Rule type**: eql

**Rule indices**:

* logs-jamf_protect*
* logs-endpoint.events.process-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.loobins.io/binaries/pbpaste/](https://www.loobins.io/binaries/pbpaste/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Jamf Protect
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Thijs Xhaflaire

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1052]

**Triage and analysis**

To investigate `pbpaste` activity, focus on determining whether the binary is being used maliciously to collect clipboard data. Follow these steps:

[TBC: QUOTE]
1. ***Identify Frequency and Pattern of Execution:***

    * ***What to check:*** Analyze the frequency and timing of `pbpaste` executions. Look for consistent intervals that might indicate a script or loop is running.
    * ***Why:*** A high volume of regular `pbpaste` executions could suggest a bash loop designed to continuously capture clipboard data.

2. ***Examine Associated Scripts or Processes:***

    * ***What to check:*** Investigate the parent processes or scripts invoking `pbpaste`. Look for any cron jobs, bash scripts, or automated tasks linked to these executions.
    * ***Why:*** Understanding what is triggering `pbpaste` can help determine if this activity is legitimate or part of a malicious attempt to gather sensitive information.
    * `!{investigate{"label":"Show events having the same parent process","providers":[[{"excluded":false,"field":"host.hostname","queryType":"phrase","value":"{host.hostname}","valueType":"string"},{"excluded":false,"field":"process.entity_id","queryType":"phrase","value":"{process.parent.entity_id}","valueType":"string"}]]}}`
    * $investigate_2

3. ***Review Clipboard Contents:***

    * ***What to check:*** If possible, capture and review the clipboard contents during `pbpaste` executions to identify if sensitive data, such as user credentials, is being targeted.
    * ***Why:*** Attackers may use `pbpaste` to harvest valuable information from the clipboard. Identifying the type of data being collected can indicate the severity of the threat.

4. ***Check for Data Exfiltration:***

    * ***What to check:*** Investigate any output files or network activity associated with `pbpaste` usage. Look for signs that the collected data is being saved to a file, transmitted over the network, or sent to an external location.
    * ***Why:*** If data is being stored or transmitted, it may be part of an exfiltration attempt. Identifying this can help prevent sensitive information from being leaked.

5. ***Correlate with User Activity:***

    * ***What to check:*** Compare the `pbpaste` activity with the user’s normal behavior and system usage patterns.
    * ***Why:*** If the `pbpaste` activity occurs during times when the user is not active, or if the user denies initiating such tasks, it could indicate unauthorized access or a compromised account.


By thoroughly investigating these aspects of `pbpaste` activity, you can determine whether this is part of a legitimate process or a potential security threat that needs to be addressed.


## Setup [_setup_661]

**Setup**

This rule requires data coming in from Jamf Protect.

**Jamf Protect Integration Setup**

Jamf Protect is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events incoming events and send data to the Elastic.

**Prerequisite Requirements:**

* Fleet is required for Jamf Protect.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Jamf Protect integration:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Jamf Protect" and select the integration to see more details about it.
* Click "Add Jamf Protect".
* Configure the integration name.
* Click "Save and Continue".


## Rule query [_rule_query_1102]

```js
sequence by host.hostname, host.id with maxspan=1m
[process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and process.name: "pbpaste"] with runs = 5
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Input Capture
    * ID: T1056
    * Reference URL: [https://attack.mitre.org/techniques/T1056/](https://attack.mitre.org/techniques/T1056/)



