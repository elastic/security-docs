---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-occurrence-of-github-user-interaction-with-private-repo.html
---

# First Occurrence of GitHub User Interaction with Private Repo [first-occurrence-of-github-user-interaction-with-private-repo]

Detects a new private repo interaction for a GitHub user not seen in the last 14 days.

**Rule type**: new_terms

**Rule indices**:

* logs-github.audit-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Use Case: UEBA
* Tactic: Execution
* Rule Type: BBR
* Data Source: Github

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_366]

```js
event.dataset:"github.audit" and event.category:"configuration" and
github.repo:* and user.name:* and
github.repository_public:false
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Serverless Execution
    * ID: T1648
    * Reference URL: [https://attack.mitre.org/techniques/T1648/](https://attack.mitre.org/techniques/T1648/)



