---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-guardduty-detector-deletion.html
---

# AWS GuardDuty Detector Deletion [aws-guardduty-detector-deletion]

Identifies the deletion of an Amazon GuardDuty detector. Upon deletion, GuardDuty stops monitoring the environment and all existing findings are lost.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/guardduty/delete-detector.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/guardduty/delete-detector.html)
* [https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html)

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

## Investigation guide [_investigation_guide_41]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS GuardDuty Detector Deletion**

AWS GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior in AWS environments. Deleting a GuardDuty detector halts this monitoring, potentially concealing malicious actions. Adversaries may exploit this by deleting detectors to evade detection. The detection rule identifies successful deletion events, signaling potential defense evasion attempts, and is crucial for maintaining security visibility.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.provider:guardduty.amazonaws.com and event.action:DeleteDetector to identify the user or role responsible for the deletion.
* Check the event.outcome:success to confirm the deletion was successful and not an attempted action.
* Investigate the IAM permissions and recent activity of the user or role identified to determine if the deletion was authorized or potentially malicious.
* Examine any recent GuardDuty findings prior to the deletion to assess if there were any critical alerts that might have prompted the deletion.
* Correlate the timing of the detector deletion with other security events or anomalies in the AWS environment to identify potential patterns or coordinated actions.
* Review AWS CloudTrail logs for any other suspicious activities or changes in the environment around the time of the detector deletion.

**False positive analysis**

* Routine maintenance or administrative actions may lead to the deletion of a GuardDuty detector. Verify if the deletion aligns with scheduled maintenance or administrative tasks.
* Automated scripts or tools used for environment cleanup might inadvertently delete detectors. Review and adjust automation scripts to prevent unintended deletions.
* Organizational policy changes or restructuring could result in detector deletions. Ensure that policy changes are communicated and understood by all relevant teams to avoid unnecessary deletions.
* Exclude known and authorized users or roles from triggering alerts by creating exceptions for specific IAM roles or user accounts that are responsible for legitimate detector deletions.
* Implement logging and alerting for detector deletions to quickly identify and verify the legitimacy of the action, allowing for rapid response to potential false positives.

**Response and remediation**

* Immediately re-enable GuardDuty in the affected AWS account to restore monitoring capabilities and ensure continuous threat detection.
* Conduct a thorough review of CloudTrail logs to identify any unauthorized access or suspicious activities that occurred during the period when GuardDuty was disabled.
* Isolate any compromised resources identified during the log review to prevent further unauthorized access or damage.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional access controls and monitoring on the AWS account to prevent unauthorized deletion of GuardDuty detectors in the future.
* Review and update IAM policies to ensure that only authorized personnel have permissions to delete GuardDuty detectors.
* Consider enabling AWS Config rules to monitor and alert on changes to GuardDuty configurations for proactive detection of similar incidents.


## Setup [_setup_27]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_42]

```js
event.dataset:aws.cloudtrail and event.provider:guardduty.amazonaws.com and event.action:DeleteDetector and event.outcome:success
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



