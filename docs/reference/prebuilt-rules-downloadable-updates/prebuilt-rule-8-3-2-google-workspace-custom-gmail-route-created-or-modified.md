---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-google-workspace-custom-gmail-route-created-or-modified.html
---

# Google Workspace Custom Gmail Route Created or Modified [prebuilt-rule-8-3-2-google-workspace-custom-gmail-route-created-or-modified]

Detects when a custom Gmail route is added or modified in Google Workspace. Adversaries can add a custom e-mail route for outbound mail to route these e-mails to their own inbox of choice for data gathering. This allows adversaries to capture sensitive information from e-mail and potential attachments, such as invoices or payment documents. By default, all email from current Google Workspace users with accounts are routed through a domain’s mail server for inbound and outbound mail.

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

* [https://support.google.com/a/answer/2685650?hl=en](https://support.google.com/a/answer/2685650?hl=en)

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

## Investigation guide [_investigation_guide_2335]

## Important Information Regarding Google Workspace Event Lag Times
- As per Google's documentation, Google Workspace administrators may observe lag times ranging from minutes up to 3 days between the time of an event's occurrence and the event being visible in the Google Workspace admin/audit logs.
- This rule is configured to run every 10 minutes with a lookback time of 130 minutes.
- To reduce the risk of false negatives, consider reducing the interval that the Google Workspace (formerly G Suite) Filebeat module polls Google's reporting API for new events.
- By default, `var.interval` is set to 2 hours (2h). Consider changing this interval to a lower value, such as 10 minutes (10m).
- See the following references for further information:
  - https://support.google.com/a/answer/7061566
  - /beats/docs/reference/ingestion-tools/beats-filebeat/filebeat-module-google_workspace.md

## Rule query [_rule_query_2700]

```js
event.dataset:"google_workspace.admin" and event.action:("CREATE_GMAIL_SETTING" or "CHANGE_GMAIL_SETTING")
  and google_workspace.event.type:"EMAIL_SETTINGS" and google_workspace.admin.setting.name:("EMAIL_ROUTE" or "MESSAGE_SECURITY_RULE")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Email Forwarding Rule
    * ID: T1114.003
    * Reference URL: [https://attack.mitre.org/techniques/T1114/003/](https://attack.mitre.org/techniques/T1114/003/)



