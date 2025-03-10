---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-remote-logon-followed-by-scheduled-task-creation.html
---

# Remote Logon followed by Scheduled Task Creation [prebuilt-rule-8-3-2-remote-logon-followed-by-scheduled-task-creation]

Identifies a remote logon followed by a scheduled task creation on the target host. This could be indicative of adversary lateral movement.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2350]

## Triage and analysis

## Investigating Remote Scheduled Task Creation

[Scheduled tasks](https://docs.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) are a great mechanism
for persistence and program execution. These features can be used remotely for a variety of legitimate reasons, but at
the same time used by malware and adversaries. When investigating scheduled tasks that were set up remotely, one of the
first steps should be to determine the original intent behind the configuration and to verify if the activity is tied to
benign behavior such as software installation or any kind of network administrator work. One objective for these alerts
is to understand the configured action within the scheduled task. This is captured within the registry event data for
this rule and can be base64 decoded to view the value.

### Possible investigation steps

- Review the TaskContent value to investigate the task configured action.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software
installations.
- Further examination should include review of host-based artifacts and network logs from around when the scheduled task
was created, on both the source and target machines.

## False positive analysis

- There is a high possibility of benign activity tied to the creation of remote scheduled tasks as it is a general feature
within Windows and used for legitimate purposes for a wide range of activity. Any kind of context should be found to
further understand the source of the activity and determine the intent based on the scheduled task's contents.

## Related rules

- Service Command Lateral Movement - d61cbcf8-1bc1-4cff-85ba-e7b21c5beedc
- Remotely Started Services via RPC - aa9a274d-6b53-424d-ac5e-cb8ca4251650
- Remote Scheduled Task Creation - 954ee7c8-5437-49ae-b2d6-2960883898e9

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Remove scheduled task and any other related artifacts.
- Review privileged account management and user account management settings. Consider implementing group policy object (GPO) policies to further
restrict activity, or configuring settings that only allow administrators to create remote scheduled tasks.

## Rule query [_rule_query_2719]

```js
/* Network Logon followed by Scheduled Task creation  */

sequence by host.id with maxspan=1m
  [authentication where event.action == "logged-in" and
   winlog.logon.type == "Network" and event.outcome == "success" and
   not user.name == "ANONYMOUS LOGON" and not winlog.event_data.SubjectUserName : "*$" and
   not user.domain == "NT AUTHORITY" and source.ip != "127.0.0.1" and source.ip !="::1"] by winlog.event_data.TargetLogonId

  [iam where event.action == "scheduled-task-created"] by winlog.event_data.SubjectLogonId
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



