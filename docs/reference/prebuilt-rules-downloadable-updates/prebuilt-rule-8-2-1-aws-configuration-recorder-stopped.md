---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-configuration-recorder-stopped.html
---

# AWS Configuration Recorder Stopped [prebuilt-rule-8-2-1-aws-configuration-recorder-stopped]

Identifies an AWS configuration change to stop recording a designated set of resources.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.md)
* [https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html](https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1838]



## Rule query [_rule_query_2128]

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



