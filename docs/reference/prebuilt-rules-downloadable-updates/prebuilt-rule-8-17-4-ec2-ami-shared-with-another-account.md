---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ec2-ami-shared-with-another-account.html
---

# EC2 AMI Shared with Another Account [prebuilt-rule-8-17-4-ec2-ami-shared-with-another-account]

Identifies an AWS Amazon Machine Image (AMI) being shared with another AWS account. Adversaries with access may share an AMI with an external AWS account as a means of data exfiltration. AMIs can contain secrets, bash histories, code artifacts, and other sensitive data that adversaries may abuse if shared with unauthorized accounts. AMIs can be made publicly available accidentally as well.

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

* [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.md)
* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Threat Detection
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4011]

**Triage and analysis**

**Investigating EC2 AMI Shared with Another Account**

This rule identifies when an Amazon Machine Image (AMI) is shared with another AWS account. While sharing AMIs is a common practice, adversaries may exploit this feature to exfiltrate data by sharing AMIs with external accounts under their control.

**Possible Investigation Steps**

* ***Review the Sharing Event***: Identify the AMI involved and review the event details in AWS CloudTrail. Look for `ModifyImageAttribute` actions where the AMI attributes were changed to include additional user accounts.
* ***Request and Response Parameters***: Check the `aws.cloudtrail.request_parameters` and `aws.response.response_elements` fields in the CloudTrail event to identify the AMI ID and the user ID of the account with which the AMI was shared.
* ***Verify the Shared AMI***: Check the AMI that was shared and its contents to determine the sensitivity of the data stored within it.
* ***Contextualize with Recent Changes***: Compare this sharing event against recent changes in AMI configurations and deployments. Look for any other recent permissions changes or unusual administrative actions.
* ***Validate External Account***: Examine the AWS account to which the AMI was shared. Determine whether this account is known and previously authorized to access such resources.
* ***Interview Relevant Personnel***: If the share was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing AMI deployments.
* ***Audit Related Security Policies***: Check the security policies governing AMI sharing within your organization to ensure they are being followed and are adequate to prevent unauthorized sharing.

**False Positive Analysis**

* ***Legitimate Sharing Practices***: AMI sharing is a common and legitimate practice for collaboration and resource management in AWS. Always verify that the sharing activity was unauthorized before escalating.
* ***Automation Tools***: Some organizations use automation tools for AMI management which might programmatically share AMIs. Verify if such tools are in operation and whether their actions are responsible for the observed behavior.

**Response and Remediation**

* ***Review and Revoke Unauthorized Shares***: If the share is found to be unauthorized, immediately revoke the shared permissions from the AMI.
* ***Enhance Monitoring of Shared AMIs***: Implement monitoring to track changes to shared AMIs and alert on unauthorized access patterns.
* ***Incident Response***: If malicious intent is confirmed, consider it a data breach incident and initiate the incident response protocol. This includes further investigation, containment, and recovery.
* ***Policy Update***: Review and possibly update your organization’s policies on AMI sharing to tighten control and prevent unauthorized access.
* ***Educate Users***: Conduct training sessions for users involved in managing AMIs to reinforce best practices and organizational policies regarding AMI sharing.

**Additional Information**

For more information on managing and sharing AMIs, refer to the [Amazon EC2 User Guide on AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.md) and [Sharing AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.md). Additionally, explore adversarial techniques related to data exfiltration via AMI sharing as documented by Stratus Red Team [here](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.ec2-share-ami/).


## Rule query [_rule_query_5028]

```js
event.dataset: "aws.cloudtrail" and event.provider: "ec2.amazonaws.com"
    and event.action: ModifyImageAttribute and event.outcome: success
    and aws.cloudtrail.request_parameters: (*imageId* and *add* and *userId*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



