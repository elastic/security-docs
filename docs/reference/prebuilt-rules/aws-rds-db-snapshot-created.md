---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-db-snapshot-created.html
---

# AWS RDS DB Snapshot Created [aws-rds-db-snapshot-created]

Identifies when an AWS RDS DB Snapshot is created. This can be used to evade defenses by allowing an attacker to bypass access controls or cover their tracks by reverting an instance to a previous state. This is a [building block rule](docs-content://solutions/security/detect-and-alert/about-building-block-rules.md) and does not generate alerts on its own. It is meant to be used for correlation with other rules to detect suspicious activity. To generate alerts, create a rule that uses this signal as a building block.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Use Case: Asset Visibility
* Tactic: Defense Evasion
* Rule Type: BBR

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_73]

```js
event.dataset: "aws.cloudtrail" and event.provider: "rds.amazonaws.com"
    and event.action: ("CreateDBSnapshot" or "CreateDBClusterSnapshot") and event.outcome: "success"
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

    * Name: Create Snapshot
    * ID: T1578.001
    * Reference URL: [https://attack.mitre.org/techniques/T1578/001/](https://attack.mitre.org/techniques/T1578/001/)



