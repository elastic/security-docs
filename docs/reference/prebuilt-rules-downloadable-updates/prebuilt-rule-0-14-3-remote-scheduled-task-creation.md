---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-remote-scheduled-task-creation.html
---

# Remote Scheduled Task Creation [prebuilt-rule-0-14-3-remote-scheduled-task-creation]

Identifies remote scheduled task creations on a target host. This could be indicative of adversary lateral movement.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1350]

## Triage and analysis

## Investigating Creation of Remote Scheduled Tasks

[Scheduled tasks](https://docs.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) are a great mechanism used for persistence and executing programs. These features can
be used remotely for a variety of legitimate reasons, but at the same time used by malware and adversaries.
When investigating scheduled tasks that have been set-up remotely, one of the first methods should be determining the
original intent behind the configuration and verify if the activity is tied to benign behavior such as software installations or any kind
of network administrator work. One objective for these alerts is to understand the configured action within the scheduled
task, this is captured within the registry event data for this rule and can be base64 decoded to view the value.

### Possible investigation steps:
- Review the base64 encoded tasks actions registry value to investigate the task configured action.
- Determine if task is related to legitimate or benign behavior based on the corresponding process or program tied to the
scheduled task.
- Further examination should include both the source and target machines where host-based artifacts and network logs
should be reviewed further around the time window of the creation of the scheduled task.

## False Positive Analysis
- There is a high possibility of benign activity tied to the creation of remote scheduled tasks as it is a general feature
within Windows and used for legitimate purposes for a wide range of activity. Any kind of context should be found to
further understand the source of the activity and determine the intent based on the scheduled task contents.

## Related Rules
- Service Command Lateral Movement
- Remotely Started Services via RPC

## Response and Remediation
- This behavior represents post-exploitation actions such as persistence or lateral movement, immediate response should
be taken to review and investigate the activity and potentially isolate involved machines to prevent further post-compromise
behavior.
- Remove scheduled task and any other related artifacts to the activity.
- Review privileged account management and user account management settings such as implementing GPO policies to further
restrict activity or configure settings that only allow Administrators to create remote scheduled tasks.

## Rule query [_rule_query_1558]

```js
/* Task Scheduler service incoming connection followed by TaskCache registry modification  */

sequence by host.id, process.entity_id with maxspan = 1m
   [network where process.name : "svchost.exe" and
   network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
   source.address != "127.0.0.1" and source.address != "::1"
   ]
   [registry where registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
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



