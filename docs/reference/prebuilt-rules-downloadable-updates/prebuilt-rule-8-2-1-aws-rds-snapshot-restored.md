---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-rds-snapshot-restored.html
---

# AWS RDS Snapshot Restored [prebuilt-rule-8-2-1-aws-rds-snapshot-restored]

Identifies when an attempt was made to restore an RDS Snapshot. Snapshots are sometimes shared by threat actors in order to exfiltrate bulk data or evade detection after performing malicious activities. If the permissions were modified, verify if the snapshot was shared with an unauthorized or unexpected AWS account.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html)
* [https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py](https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility
* Defense Evasion

**Version**: 5

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1851]



## Rule query [_rule_query_2141]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:RestoreDBInstanceFromDBSnapshot and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Cloud Compute Infrastructure
    * ID: T1578
    * Reference URL: [https://attack.mitre.org/techniques/T1578/](https://attack.mitre.org/techniques/T1578/)

* Sub-technique:

    * Name: Revert Cloud Instance
    * ID: T1578.004
    * Reference URL: [https://attack.mitre.org/techniques/T1578/004/](https://attack.mitre.org/techniques/T1578/004/)



