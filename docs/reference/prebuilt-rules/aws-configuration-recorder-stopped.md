---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-configuration-recorder-stopped.html
---

# AWS Configuration Recorder Stopped [aws-configuration-recorder-stopped]

Identifies an AWS configuration change to stop recording a designated set of resources.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.md)
* [https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html](https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_18]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Configuration Recorder Stopped**

AWS Config records and evaluates configurations of AWS resources, ensuring compliance and security. Stopping the configuration recorder can hinder visibility into resource changes, aiding adversaries in evading detection. The detection rule identifies successful attempts to stop the recorder, signaling potential defense evasion by monitoring specific AWS CloudTrail events related to configuration changes.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.action:StopConfigurationRecorder to identify the user or role that initiated the action.
* Check the event.outcome:success field to confirm the action was successfully executed and correlate it with any other suspicious activities around the same timeframe.
* Investigate the IAM permissions and roles associated with the user or entity that stopped the configuration recorder to determine if they have the necessary permissions and if those permissions are appropriate.
* Analyze the context of the event by examining other recent AWS CloudTrail events from the same event.provider:config.amazonaws.com to identify any related configuration changes or anomalies.
* Assess the potential impact on compliance and security by identifying which resources were affected by the stopped configuration recorder and evaluating the risk of undetected changes during the period it was inactive.
* Review any recent changes in AWS Config settings or policies that might explain the legitimate need to stop the configuration recorder, ensuring there is a valid business justification.

**False positive analysis**

* Routine maintenance activities by authorized personnel can trigger the rule. To manage this, create exceptions for specific IAM roles or users known to perform these tasks regularly.
* Automated scripts or tools used for configuration management might stop the recorder as part of their operation. Identify these scripts and exclude their actions from triggering alerts by using their unique identifiers or tags.
* Scheduled configuration changes during non-peak hours may involve stopping the recorder temporarily. Document these schedules and adjust the rule to ignore events during these periods.
* Testing environments often mimic production changes, including stopping the recorder. Exclude events from known testing accounts or environments to prevent unnecessary alerts.

**Response and remediation**

* Immediately re-enable the AWS Config recorder to restore visibility into resource changes and ensure compliance monitoring is active.
* Conduct a thorough review of AWS CloudTrail logs to identify any unauthorized or suspicious activities that occurred during the period when the configuration recorder was stopped.
* Verify the IAM roles and permissions associated with the AWS account to ensure that only authorized personnel have the ability to stop the configuration recorder. Adjust permissions as necessary to follow the principle of least privilege.
* Implement additional monitoring and alerting for any future attempts to stop the AWS Config recorder, ensuring that such actions trigger immediate notifications to the security team.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if the action was part of a broader attack or misconfiguration.
* Review and update incident response plans to include specific procedures for handling AWS Config recorder stoppage events, ensuring rapid response and containment in future occurrences.
* Consider enabling AWS Config rules to automatically remediate unauthorized changes, such as stopping the configuration recorder, to enhance the security posture and prevent recurrence.


## Setup [_setup_15]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_18]

```js
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and event.action:StopConfigurationRecorder and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



