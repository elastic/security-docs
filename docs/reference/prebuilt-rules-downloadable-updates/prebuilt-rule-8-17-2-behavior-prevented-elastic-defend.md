---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-behavior-prevented-elastic-defend.html
---

# Behavior - Prevented - Elastic Defend [prebuilt-rule-8-17-2-behavior-prevented-elastic-defend]

Generates a detection alert each time an Elastic Defend alert for malicious behavior is received. Enabling this rule allows you to immediately begin investigating your Endpoint behavior alerts. This rule identifies Elastic Defend behavior preventions only, and does not include detection only alerts.

**Rule type**: query

**Rule indices**:

* logs-endpoint.alerts-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**:

* [https://github.com/elastic/protections-artifacts/tree/main/behavior](https://github.com/elastic/protections-artifacts/tree/main/behavior)
* [https://docs.elastic.co/en/integrations/endpoint](https://docs.elastic.co/en/integrations/endpoint)

**Tags**:

* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3898]

**Triage and analysis**

**Investigating Behavior Alerts**

Malicious behavior protection is a foundational feature which can be used to protect against all manner of attacks on the endpoint. For example, it provides coverage against phishing such as malicious macros, many malware families based on their activities, privilege escalation attacks such as user account control bypasses (UAC), credential theft, and much more. It works by consuming an unfiltered feed of all events that are captured on the system (process, file, registry, network, dns, etc). These events are processed against a routinely updated set of rules written by Elastic threat experts. From there, malicious behaviors are identified and offending processes are terminated. The protection operates on the event stream asynchronously, but has been designed to be extremely efficient and typically requires just milliseconds (under standard load) to stop malicious activity.

**Possible investigation steps**

* Assess whether this activity is prevalent in your environment by looking for similar occurrences across hosts.
* Verify the detailed activity of the process that triggered the alert (process tree, child process, process arguments, network, files, libraries and registry events).
* Verify the activity of the `user.name` associated with the alert (local or remote actity, privileged or standard user).
* Particular attention should be paid to instances where the same process is triggering multiple alerts (more than 2 or 3) within a short period of time.
* Even the the process is signed by a valid certificate, verify the if it’s running from the expected location or if it’s loading any suspicious libraries or any sign of code injection.

**False positive analysis**

* Same alert observed on a high number of hosts with similar details.
* High count of the same alert on a specific host over a long period of time.

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Implement Elastic Endpoint Security to detect and prevent further post exploitation activities in the environment.
* Contain the affected system by isolating it from the network to prevent further spread of the attack.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Restore the affected system to its operational state by applying any necessary patches, updates, or configuration changes.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_775]

**Setup**

**Elastic Defend Alerts**

This rule is designed to capture specific alerts generated by Elastic Defend.

To capture all the Elastic Defend alerts, it is recommended to use all of the Elastic Defend feature-specific protection rules:

Behavior - Detected - Elastic Defend (UUID: 0f615fe4-eaa2-11ee-ae33-f661ea17fbce) Behavior - Prevented - Elastic Defend (UUID: eb804972-ea34-11ee-a417-f661ea17fbce) Malicious File - Detected - Elastic Defend (UUID: f2c3caa6-ea34-11ee-a417-f661ea17fbce) Malicious File - Prevented - Elastic Defend (UUID: f87e6122-ea34-11ee-a417-f661ea17fbce) Memory Threat - Detected - Elastic Defend (UUID: 017de1e4-ea35-11ee-a417-f661ea17fbce) Memory Threat - Prevented - Elastic Defend (UUID: 06f3a26c-ea35-11ee-a417-f661ea17fbce) Ransomware - Detected - Elastic Defend (UUID: 0c74cd7e-ea35-11ee-a417-f661ea17fbce) Ransomware - Prevented - Elastic Defend (UUID: 10f3d520-ea35-11ee-a417-f661ea17fbce)

To avoid generating duplicate alerts, you should enable either all feature-specific protection rules or the Endpoint Security (Elastic Defend) rule (UUID: 9a1a2dae-0b5f-4c3d-8305-a268d404c306).

**Additional notes**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_4793]

```js
event.kind : alert and event.code : behavior and event.type : denied and event.outcome : success
```


