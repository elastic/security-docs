---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kubernetes-suspicious-self-subject-review.html
---

# Kubernetes Suspicious Self-Subject Review [kubernetes-suspicious-self-subject-review]

This rule detects when a service account or node attempts to enumerate their own permissions via the selfsubjectaccessreview or selfsubjectrulesreview APIs. This is highly unusual behavior for non-human identities like service accounts and nodes. An adversary may have gained access to credentials/tokens and this could be an attempt to determine what privileges they have to facilitate further movement or execution within the cluster.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/kubernetes-privilege-escalation-excessive-permissions-in-popular-platforms)
* [https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)
* [https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/detecting-identity-attacks-in-kubernetes/ba-p/3232340](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/detecting-identity-attacks-in-kubernetes/ba-p/3232340)

**Tags**:

* Data Source: Kubernetes
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_465]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Kubernetes Suspicious Self-Subject Review**

Kubernetes uses APIs like selfsubjectaccessreview and selfsubjectrulesreview to allow entities to check their own permissions. While useful for debugging, adversaries can exploit these APIs to assess their access level after compromising service accounts or nodes. The detection rule identifies unusual API calls by non-human identities, flagging potential unauthorized privilege enumeration attempts.

**Possible investigation steps**

* Review the Kubernetes audit logs to identify the specific service account or node that triggered the alert by examining the kubernetes.audit.user.username or kubernetes.audit.impersonatedUser.username fields.
* Check the context of the API call by analyzing the kubernetes.audit.objectRef.resource field to confirm whether it involved selfsubjectaccessreviews or selfsubjectrulesreviews.
* Investigate the source of the API request by looking at the IP address and user agent in the audit logs to determine if the request originated from a known or expected source.
* Assess the recent activity of the implicated service account or node to identify any unusual patterns or deviations from normal behavior.
* Verify if there have been any recent changes to the permissions or roles associated with the service account or node to understand if the access level has been altered.
* Cross-reference the alert with any other security events or alerts in the environment to determine if this is part of a broader attack or compromise.

**False positive analysis**

* Service accounts used for automated tasks may trigger this rule if they are programmed to check permissions as part of their routine operations. To handle this, identify these accounts and create exceptions for their specific API calls.
* Nodes performing legitimate self-assessment for compliance or security checks might be flagged. Review the node’s purpose and, if necessary, whitelist these actions in the detection rule.
* Development or testing environments where permissions are frequently checked by service accounts can generate false positives. Consider excluding these environments from the rule or adjusting the rule’s sensitivity for these specific contexts.
* Regularly scheduled jobs or scripts that include permission checks as part of their execution may cause alerts. Document these jobs and adjust the rule to ignore these specific, non-threatening behaviors.

**Response and remediation**

* Immediately isolate the compromised service account or node by revoking its access tokens and credentials to prevent further unauthorized actions within the cluster.
* Conduct a thorough review of the audit logs to identify any other suspicious activities or access patterns associated with the compromised identity, focusing on any lateral movement or privilege escalation attempts.
* Rotate credentials and tokens for all service accounts and nodes that may have been exposed or compromised, ensuring that new credentials are distributed securely.
* Implement network segmentation and access controls to limit the ability of compromised identities to interact with sensitive resources or other parts of the cluster.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been affected.
* Enhance monitoring and alerting for similar suspicious activities by tuning detection systems to recognize patterns of unauthorized privilege enumeration attempts.
* Review and update Kubernetes role-based access control (RBAC) policies to ensure that service accounts and nodes have the minimum necessary permissions, reducing the risk of privilege abuse.


## Setup [_setup_300]

The Kubernetes Fleet integration with Audit Logs enabled or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_500]

```js
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb:"create"
  and kubernetes.audit.objectRef.resource:("selfsubjectaccessreviews" or "selfsubjectrulesreviews")
  and (kubernetes.audit.user.username:(system\:serviceaccount\:* or system\:node\:*)
  or kubernetes.audit.impersonatedUser.username:(system\:serviceaccount\:* or system\:node\:*))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Container and Resource Discovery
    * ID: T1613
    * Reference URL: [https://attack.mitre.org/techniques/T1613/](https://attack.mitre.org/techniques/T1613/)



