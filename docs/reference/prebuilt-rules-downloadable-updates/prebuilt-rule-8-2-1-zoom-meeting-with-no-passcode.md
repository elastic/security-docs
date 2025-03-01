---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-zoom-meeting-with-no-passcode.html
---

# Zoom Meeting with no Passcode [prebuilt-rule-8-2-1-zoom-meeting-with-no-passcode]

This rule identifies Zoom meetings that are created without a passcode. Meetings without a passcode are susceptible to Zoombombing. Zoombombing is carried out by taking advantage of Zoom sessions that are not protected with a passcode. Zoombombing refers to the unwanted, disruptive intrusion, generally by Internet trolls and hackers, into a video conference call. In a typical Zoombombing incident, a teleconferencing session is hijacked by the insertion of material that is lewd, obscene, racist, or antisemitic in nature, typically resulting of the shutdown of the session.

**Rule type**: query

**Rule indices**:

* filebeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.zoom.us/a-message-to-our-users/](https://blog.zoom.us/a-message-to-our-users/)
* [https://www.fbi.gov/contact-us/field-offices/boston/news/press-releases/fbi-warns-of-teleconferencing-and-online-classroom-hijacking-during-covid-19-pandemic](https://www.fbi.gov/contact-us/field-offices/boston/news/press-releases/fbi-warns-of-teleconferencing-and-online-classroom-hijacking-during-covid-19-pandemic)

**Tags**:

* Elastic
* Application
* Communication
* Zoom
* Continuous Monitoring
* SecOps
* Configuration Audit

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1828]



## Rule query [_rule_query_2118]

```js
event.type:creation and event.module:zoom and event.dataset:zoom.webhook and
  event.action:meeting.created and not zoom.meeting.password:*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



