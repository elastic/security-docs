---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-occurrence-of-ip-address-for-github-personal-access-token-pat.html
---

# First Occurrence of IP Address For GitHub Personal Access Token (PAT) [first-occurrence-of-ip-address-for-github-personal-access-token-pat]

Detects a new IP address used for a GitHub PAT not previously seen in the last 14 days.

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
* Tactic: Initial Access
* Rule Type: BBR
* Data Source: Github

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_367]

```js
event.dataset:"github.audit" and event.category:"configuration" and
github.actor_ip:* and github.hashed_token:* and
github.programmatic_access_type:("OAuth access token" or "Fine-grained personal access token")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)



