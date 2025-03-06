---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-ec2-full-network-packet-capture-detected.html
---

# AWS EC2 Full Network Packet Capture Detected [aws-ec2-full-network-packet-capture-detected]

Identifies potential Traffic Mirroring in an Amazon Elastic Compute Cloud (EC2) instance. Traffic Mirroring is an Amazon VPC feature that you can use to copy network traffic from an Elastic network interface. This feature can potentially be abused to exfiltrate sensitive data from unencrypted internal traffic.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorFilter.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TrafficMirrorFilter.html)
* [https://github.com/easttimor/aws-incident-response](https://github.com/easttimor/aws-incident-response)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Network Security Monitoring
* Tactic: Exfiltration
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_26]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Full Network Packet Capture Detected**

Traffic Mirroring in AWS EC2 allows copying of network traffic for monitoring and analysis, crucial for security and performance insights. However, adversaries can exploit this by capturing unencrypted data, leading to potential data exfiltration. The detection rule identifies successful creation of traffic mirroring components, signaling possible misuse for unauthorized data collection.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event actions: CreateTrafficMirrorFilter, CreateTrafficMirrorFilterRule, CreateTrafficMirrorSession, and CreateTrafficMirrorTarget to identify the user or role that initiated these actions.
* Check the event.outcome field to confirm the success of the traffic mirroring setup and gather details about the time and source IP address of the request.
* Investigate the associated Elastic Network Interface (ENI) to determine which EC2 instance is involved and assess its role and importance within the network.
* Analyze the network traffic patterns and data flow from the mirrored traffic to identify any signs of data exfiltration or unusual data transfer activities.
* Verify the encryption status of the network traffic being mirrored to assess the risk of sensitive data exposure.
* Cross-reference the involved AWS account and IAM roles with known threat actor profiles or previous security incidents to identify potential insider threats or compromised accounts.

**False positive analysis**

* Routine network monitoring activities may trigger the rule if legitimate traffic mirroring is set up for performance analysis. To manage this, identify and document authorized traffic mirroring configurations and exclude them from alerts.
* Security audits or compliance checks might involve creating traffic mirroring sessions. Coordinate with audit teams to schedule these activities and temporarily suppress alerts during these periods.
* Development and testing environments often use traffic mirroring for debugging purposes. Maintain a list of such environments and apply exceptions to avoid unnecessary alerts.
* Automated infrastructure management tools might create traffic mirroring components as part of their operations. Review and whitelist these tools to prevent false positives.
* Ensure that any third-party services with access to your AWS environment are vetted and their activities are monitored to distinguish between legitimate and suspicious traffic mirroring actions.

**Response and remediation**

* Immediately isolate the affected EC2 instance to prevent further data exfiltration. This can be done by removing the instance from any network access or security groups that allow outbound traffic.
* Review and terminate any unauthorized Traffic Mirroring sessions, filters, or targets that were created. Ensure that only legitimate and necessary mirroring configurations are active.
* Conduct a thorough audit of the AWS CloudTrail logs to identify any other suspicious activities or unauthorized access attempts related to Traffic Mirroring or other sensitive operations.
* Rotate and update any credentials or access keys that may have been exposed or compromised during the incident to prevent further unauthorized access.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation. Escalate to higher management if the data exfiltration involves sensitive or critical data.
* Implement additional network monitoring and intrusion detection measures to enhance visibility and detect similar threats in the future. Consider using AWS GuardDuty or similar services for continuous threat detection.
* Review and update security policies and access controls to ensure that Traffic Mirroring and other sensitive features are only accessible to authorized personnel with a legitimate need.


## Setup [_setup_18]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_26]

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



