---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-google-drive-ownership-transferred-via-google-workspace.html
---

# Google Drive Ownership Transferred via Google Workspace [prebuilt-rule-8-3-2-google-drive-ownership-transferred-via-google-workspace]

Drive and Docs is a Google Workspace service that allows users to leverage Google Drive and Google Docs. Access to files is based on inherited permissions from the child organizational unit the user belongs to which is scoped by administrators. Typically if a user is removed, their files can be transferred to another user by the administrator. This service can also be abused by adversaries to transfer files to an adversary account for potential exfiltration.

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

* [https://support.google.com/a/answer/1247799?hl=en](https://support.google.com/a/answer/1247799?hl=en)

**Tags**:

* Elastic
* Cloud
* Google Workspace
* Continuous Monitoring
* SecOps
* Collection

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2334]

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - /beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md

## Rule query [_rule_query_2699]

```js
event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
  and event.category:"iam" and google_workspace.admin.application.name:Drive*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data Staged
    * ID: T1074
    * Reference URL: [https://attack.mitre.org/techniques/T1074/](https://attack.mitre.org/techniques/T1074/)

* Sub-technique:

    * Name: Remote Data Staging
    * ID: T1074.002
    * Reference URL: [https://attack.mitre.org/techniques/T1074/002/](https://attack.mitre.org/techniques/T1074/002/)



