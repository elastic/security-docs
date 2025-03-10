---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-aws-ec2-full-network-packet-capture-detected.html
---

# AWS EC2 Full Network Packet Capture Detected [prebuilt-rule-0-14-1-aws-ec2-full-network-packet-capture-detected]

Identifies potential Traffic Mirroring in an Amazon Elastic Compute Cloud (EC2) instance. Traffic Mirroring is an Amazon VPC feature that you can use to copy network traffic from an Elastic network interface. This feature can potentially be abused to exfiltrate sensitive data from unencrypted internal traffic.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorFilter.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorFilter.md)
* [https://github.com/easttimor/aws-incident-response](https://github.com/easttimor/aws-incident-response)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 2

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1257]

## Config

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1335]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and
event.action:(CreateTrafficMirrorFilter or CreateTrafficMirrorFilterRule or CreateTrafficMirrorSession or CreateTrafficMirrorTarget) and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Automated Exfiltration
    * ID: T1020
    * Reference URL: [https://attack.mitre.org/techniques/T1020/](https://attack.mitre.org/techniques/T1020/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data Staged
    * ID: T1074
    * Reference URL: [https://attack.mitre.org/techniques/T1074/](https://attack.mitre.org/techniques/T1074/)



