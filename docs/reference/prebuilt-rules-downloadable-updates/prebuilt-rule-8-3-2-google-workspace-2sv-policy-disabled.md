---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-google-workspace-2sv-policy-disabled.html
---

# Google Workspace 2SV Policy Disabled [prebuilt-rule-8-3-2-google-workspace-2sv-policy-disabled]

Google Workspace admins may setup 2-step verification (2SV) to add an extra layer of security to user accounts by asking users to verify their identity when they use login credentials. Admins have the ability to enforce 2SV from the admin console as well as the methods acceptable for verification and enrollment period. 2SV requires enablement on admin accounts prior to it being enabled for users within organization units. Adversaries may disable 2SV to lower the security requirements to access a valid account.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-google_workspace*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-130m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.google.com/a/answer/9176657?hl=en](https://support.google.com/a/answer/9176657?hl=en)

**Tags**:

* Elastic
* Cloud
* Google Workspace
* Continuous Monitoring
* SecOps
* Configuration Audit
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2339]

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - /beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md

## Rule query [_rule_query_2704]

```js
event.dataset:"google_workspace.admin" and event.action:"2sv_disable"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



