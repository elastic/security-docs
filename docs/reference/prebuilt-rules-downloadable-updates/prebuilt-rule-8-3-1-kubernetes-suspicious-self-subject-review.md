---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-kubernetes-suspicious-self-subject-review.html
---

# Kubernetes Suspicious Self-Subject Review [prebuilt-rule-8-3-1-kubernetes-suspicious-self-subject-review]

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

* Elastic
* Kubernetes
* Continuous Monitoring
* Discovery

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2286]



## Rule query [_rule_query_2624]

```js
kubernetes.audit.verb:"create"
and kubernetes.audit.objectRef.resource:("selfsubjectaccessreviews" or "selfsubjectrulesreviews")
and kubernetes.audit.user.username:(system\:serviceaccount\:* or system\:node\:*) or kubernetes.audit.impersonatedUser.username:(system\:serviceaccount\:* or system\:node\:*)
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



