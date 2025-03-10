---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-azure-full-network-packet-capture-detected.html
---

# Azure Full Network Packet Capture Detected [prebuilt-rule-8-17-4-azure-full-network-packet-capture-detected]

Identifies potential full network packet capture in Azure. Packet Capture is an Azure Network Watcher feature that can be used to inspect network traffic. This feature can potentially be abused to read sensitive data from unencrypted internal traffic.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations](https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4082]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Azure Full Network Packet Capture Detected**

Azure’s Packet Capture is a feature of Network Watcher that allows for the inspection of network traffic, useful for diagnosing network issues. However, if misused, it can capture sensitive data from unencrypted traffic, posing a security risk. Adversaries might exploit this to access credentials or other sensitive information. The detection rule identifies suspicious packet capture activities by monitoring specific Azure activity logs for successful operations, helping to flag potential misuse.

**Possible investigation steps**

* Review the Azure activity logs to identify the specific user or service principal associated with the packet capture operation by examining the `azure.activitylogs.operation_name` and `event.dataset` fields.
* Check the timestamp of the detected packet capture activity to determine the exact time frame of the event and correlate it with any other suspicious activities or changes in the environment.
* Investigate the source and destination IP addresses involved in the packet capture to understand the scope and potential impact, focusing on any unencrypted traffic that might have been captured.
* Verify the legitimacy of the packet capture request by contacting the user or team responsible for the operation to confirm if it was authorized and necessary for troubleshooting or other legitimate purposes.
* Assess the risk of exposed sensitive data by identifying any critical systems or services that were part of the captured network traffic, especially those handling credentials or personal information.

**False positive analysis**

* Routine network diagnostics by authorized personnel can trigger the rule. To manage this, create exceptions for specific user accounts or IP addresses known to perform regular diagnostics.
* Automated network monitoring tools might initiate packet captures as part of their normal operations. Identify these tools and exclude their activities from triggering alerts.
* Scheduled maintenance activities often involve packet captures for performance analysis. Document these schedules and configure the rule to ignore captures during these periods.
* Development and testing environments may frequently use packet capture for debugging purposes. Exclude these environments by filtering based on resource tags or environment identifiers.
* Legitimate security audits may involve packet capture to assess network security. Coordinate with the audit team to whitelist their activities during the audit period.

**Response and remediation**

* Immediately isolate the affected network segment to prevent further unauthorized packet capture and potential data exfiltration.
* Revoke any suspicious or unauthorized access to Azure Network Watcher and related resources to prevent further misuse.
* Conduct a thorough review of the captured network traffic logs to identify any sensitive data exposure and assess the potential impact.
* Reset credentials and access tokens for any accounts or services that may have been compromised due to exposed unencrypted traffic.
* Implement network encryption protocols to protect sensitive data in transit and reduce the risk of future packet capture exploitation.
* Escalate the incident to the security operations team for further investigation and to determine if additional security measures are necessary.
* Enhance monitoring and alerting for Azure Network Watcher activities to detect and respond to similar threats more effectively in the future.


## Setup [_setup_971]

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5099]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE
    ) and
event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Network Sniffing
    * ID: T1040
    * Reference URL: [https://attack.mitre.org/techniques/T1040/](https://attack.mitre.org/techniques/T1040/)



