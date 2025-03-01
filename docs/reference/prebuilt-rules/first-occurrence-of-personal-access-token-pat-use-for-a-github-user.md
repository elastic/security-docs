---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-occurrence-of-personal-access-token-pat-use-for-a-github-user.html
---

# First Occurrence of Personal Access Token (PAT) Use For a GitHub User [first-occurrence-of-personal-access-token-pat-use-for-a-github-user]

A new PAT was used for a GitHub user not previously seen in the last 14 days.

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
* Tactic: Persistence
* Rule Type: BBR
* Data Source: Github

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_370]

```js
event.dataset:"github.audit" and event.category:"configuration" and
github.hashed_token:* and user.name:* and
github.programmatic_access_type:("OAuth access token" or "Fine-grained personal access token")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Credentials
    * ID: T1098.001
    * Reference URL: [https://attack.mitre.org/techniques/T1098/001/](https://attack.mitre.org/techniques/T1098/001/)



