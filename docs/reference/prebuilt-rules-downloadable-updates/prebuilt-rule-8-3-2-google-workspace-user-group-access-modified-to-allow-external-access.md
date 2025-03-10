---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-google-workspace-user-group-access-modified-to-allow-external-access.html
---

# Google Workspace User Group Access Modified to Allow External Access [prebuilt-rule-8-3-2-google-workspace-user-group-access-modified-to-allow-external-access]

User groups in Google Workspace are created to help manage users permissions and access to various resources and applications. The security label is only applied to a group when users within that group are expected to access sensitive data and/or resources so administrators add this label to easily manage security groups better. Adversaries with administrator access may modify a security group to allow external access from members outside the organization. This detection does not capture all modifications to security groups, but only those that could increase the risk associated with them.

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

* [https://support.google.com/a/answer/9468710?hl=en](https://support.google.com/a/answer/9468710?hl=en)

**Tags**:

* Elastic
* Cloud
* Google Workspace
* Continuous Monitoring
* SecOps
* Identity and Access
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2340]

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - /beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md

## Rule query [_rule_query_2705]

```js
event.dataset:"google_workspace.admin" and event.action:"CHANGE_GROUP_SETTING" and event.category:"iam"
    and ((google_workspace.admin.setting.name:"ALLOW_EXTERNAL_MEMBERS" and google_workspace.admin.new_value:"true")
        or (google_workspace.admin.setting.name:"WHO_CAN_JOIN" and not (google_workspace.admin.new_value:"INVITED_CAN_JOIN"
            or google_workspace.admin.new_value:"CAN_REQUEST_TO_JOIN")))
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

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)



