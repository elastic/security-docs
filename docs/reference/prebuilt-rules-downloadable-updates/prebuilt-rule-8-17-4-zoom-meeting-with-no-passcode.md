---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-zoom-meeting-with-no-passcode.html
---

# Zoom Meeting with no Passcode [prebuilt-rule-8-17-4-zoom-meeting-with-no-passcode]

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

* Data Source: Zoom
* Use Case: Configuration Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3969]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Zoom Meeting with no Passcode**

Zoom meetings without passcodes are vulnerable to unauthorized access, known as Zoombombing, where intruders disrupt sessions with inappropriate content. Adversaries exploit this by joining unsecured meetings to cause chaos or gather sensitive information. The detection rule identifies such meetings by monitoring Zoom event logs for sessions created without a passcode, helping to mitigate potential security breaches.

**Possible investigation steps**

* Review the Zoom event logs to identify the specific meeting details, including the meeting ID and the organizer’s information, using the fields event.type, event.module, event.dataset, and event.action.
* Contact the meeting organizer to verify if the meeting was intentionally created without a passcode and understand the context or purpose of the meeting.
* Check for any unusual or unauthorized participants who joined the meeting by examining the participant logs associated with the meeting ID.
* Assess if any sensitive information was discussed or shared during the meeting that could have been exposed to unauthorized participants.
* Evaluate the need to implement additional security measures, such as enabling passcodes for all future meetings or using waiting rooms to control participant access.

**False positive analysis**

* Internal team meetings may be scheduled without a passcode for convenience, especially if all participants are within a secure network. To handle this, create exceptions for meetings initiated by trusted internal users or within specific IP ranges.
* Recurring meetings with a consistent group of participants might not use passcodes to simplify access. Consider excluding these meetings by identifying and whitelisting their unique meeting IDs.
* Training sessions or webinars intended for a broad audience might be set up without passcodes to ease access. Implement a policy to review and approve such meetings in advance, ensuring they are legitimate and necessary.
* Meetings created by automated systems or bots for integration purposes may not require passcodes. Identify these systems and exclude their meeting creation events from triggering alerts.
* In some cases, meetings may be intentionally left without passcodes for public access, such as community events. Establish a process to verify and document these events, allowing them to be excluded from the rule.

**Response and remediation**

* Immediately terminate any ongoing Zoom meetings identified without a passcode to prevent further unauthorized access or disruption.
* Notify the meeting host and relevant stakeholders about the security incident, advising them to reschedule the meeting with appropriate security measures, such as enabling a passcode or waiting room.
* Review and update Zoom account settings to enforce mandatory passcodes for all future meetings, ensuring compliance with security policies.
* Conduct a security audit of recent Zoom meetings to identify any other sessions that may have been created without a passcode and take corrective actions as necessary.
* Escalate the incident to the IT security team for further investigation and to assess any potential data breaches or information leaks resulting from the unauthorized access.
* Implement enhanced monitoring and alerting for Zoom meeting creation events to quickly detect and respond to any future instances of meetings being set up without passcodes.
* Coordinate with the communications team to prepare a response plan for any potential public relations issues arising from the incident, ensuring clear and consistent messaging.


## Setup [_setup_917]

**Setup**

The Zoom Filebeat module or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_4986]

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



