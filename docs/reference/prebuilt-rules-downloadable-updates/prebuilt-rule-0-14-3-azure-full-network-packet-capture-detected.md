---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-azure-full-network-packet-capture-detected.html
---

# Azure Full Network Packet Capture Detected [prebuilt-rule-0-14-3-azure-full-network-packet-capture-detected]

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

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 1

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1330]

## Config

The Azure Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1493]

```js
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        "MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE"
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



