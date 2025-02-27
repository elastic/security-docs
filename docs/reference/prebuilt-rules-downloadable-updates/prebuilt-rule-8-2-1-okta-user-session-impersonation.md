---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-okta-user-session-impersonation.html
---

# Okta User Session Impersonation [prebuilt-rule-8-2-1-okta-user-session-impersonation]

A user has initiated a session impersonation granting them access to the environment with the permissions of the user they are impersonating. This would likely indicate Okta administrative access and should only ever occur if requested and expected.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: high

**Risk score**: 73

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.cloudflare.com/cloudflare-investigation-of-the-january-2022-okta-compromise/](https://blog.cloudflare.com/cloudflare-investigation-of-the-january-2022-okta-compromise/)

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Identity and Access
* Credential Access

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2001]



## Rule query [_rule_query_2286]

```js
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



