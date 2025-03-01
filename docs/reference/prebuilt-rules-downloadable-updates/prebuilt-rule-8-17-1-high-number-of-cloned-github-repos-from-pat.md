---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-high-number-of-cloned-github-repos-from-pat.html
---

# High Number of Cloned GitHub Repos From PAT [prebuilt-rule-8-17-1-high-number-of-cloned-github-repos-from-pat]

Detects a high number of unique private repo clone events originating from a single personal access token within a short time period.

**Rule type**: threshold

**Rule indices**:

* logs-github.audit-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Use Case: UEBA
* Tactic: Execution
* Data Source: Github

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4787]

```js
event.dataset:"github.audit" and event.category:"configuration" and event.action:"git.clone" and
github.programmatic_access_type:("OAuth access token" or "Fine-grained personal access token") and
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



