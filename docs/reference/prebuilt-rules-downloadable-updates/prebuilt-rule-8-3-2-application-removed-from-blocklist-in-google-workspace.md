---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-application-removed-from-blocklist-in-google-workspace.html
---

# Application Removed from Blocklist in Google Workspace [prebuilt-rule-8-3-2-application-removed-from-blocklist-in-google-workspace]

Google Workspace administrators may be aware of malicious applications within the Google marketplace and block these applications for user security purposes. An adversary, with administrative privileges, may remove this application from the explicit block list to allow distribution of the application amongst users. This may also indicate the unauthorized use of an application that had been previously blocked before by a user with admin privileges.

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

* [https://support.google.com/a/answer/6328701?hl=en#](https://support.google.com/a/answer/6328701?hl=en#)

**Tags**:

* Elastic
* Cloud
* Google Workspace
* Continuous Monitoring
* SecOps
* Configuration Audit
* Impair Defenses

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2336]

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - /beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md

## Rule query [_rule_query_2701]

```js
event.dataset:"google_workspace.admin" and event.category:"iam" and event.type:"change"  and
  event.action:"CHANGE_APPLICATION_SETTING" and
  google_workspace.admin.application.name:"Google Workspace Marketplace" and
  google_workspace.admin.old_value: *allowed*false* and google_workspace.admin.new_value: *allowed*true*
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



