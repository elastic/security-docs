---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/user-added-to-the-admin-group.html
---

# User Added to the Admin Group [user-added-to-the-admin-group]

Identifies users being added to the admin group. This could be an indication of privilege escalation activity.

**Rule type**: eql

**Rule indices**:

* logs-jamf_protect*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.loobins.io/binaries/dscl/](https://www.loobins.io/binaries/dscl/)
* [https://managingosx.wordpress.com/2010/01/14/add-a-user-to-the-admin-group-via-command-line-3-0/](https://managingosx.wordpress.com/2010/01/14/add-a-user-to-the-admin-group-via-command-line-3-0/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Jamf Protect
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Thijs Xhaflaire

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1175]

**Triage and analysis**

To thoroughly investigate the actions that occurred ***after a user was elevated to administrator***, it’s essential to conduct a search on the Timeline. This allows you to review and understand the sequence of events that followed the elevation, helping to identify any potentially malicious or unauthorized activities that might have taken place. ***Analyzing these actions is crucial for maintaining security and ensuring that the elevation was not exploited for harmful purposes.***

[TBC: QUOTE]
***Consider reviewing these actions:***

* Have persistency items been added?
* Is any software installed after elevation?
* Were any additional users created after elevation?

```
!{investigate{"label":"Show events after Privilege Escalation","providers":[[{"excluded":false,"field":"host.hostname","queryType":"phrase","value":"{host.hostname}","valueType":"string"}]],"relativeFrom":"now","relativeTo":"now+30m"}} !{investigate{"label":"Show events having the same reponsible process","providers":[[{"excluded":false,"field":"host.hostname","queryType":"phrase","value":"{host.hostname}","valueType":"string"},{"excluded":false,"field":"process.entity_id","queryType":"phrase","value":"{process.group_leader.entity_id}","valueType":"string"}]]}} !{investigate{"label":"Show events having the same parent process","providers":[[{"excluded":false,"field":"host.hostname","queryType":"phrase","value":"{host.hostname}","valueType":"string"},{"excluded":false,"field":"process.entity_id","queryType":"phrase","value":"{process.parent.entity_id}","valueType":"string"}]]}}
```

## Setup [_setup_746]

**Setup**

This rule requires data coming in from Jamf Protect.

**Jamf Protect Integration Setup**

Jamf Protect is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events incoming events and send data to the Elastic.

**Prerequisite Requirements:**

* Fleet is required for Jamf Protect.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Jamf Protect integration:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Jamf Protect" and select the integration to see more details about it.
* Click "Add Jamf Protect".
* Configure the integration name.
* Click "Save and Continue".


## Rule query [_rule_query_1198]

```js
configuration where host.os.type == "macos" and event.type == "change" and
  event.action == "od_group_add" and group.name:"admin"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



