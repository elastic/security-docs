---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-kubernetes-exposed-service-created-with-type-nodeport.html
---

# Kubernetes Exposed Service Created With Type NodePort [prebuilt-rule-8-2-1-kubernetes-exposed-service-created-with-type-nodeport]

This rule detects an attempt to create or modify a service as type NodePort. The NodePort service allows a user to externally expose a set of labeled pods to the internet. This creates an open port on every worker node in the cluster that has a pod for that service. When external traffic is received on that open port, it directs it to the specific pod through the service representing it. A malicious user can configure a service as type Nodeport in order to intercept traffic from other pods or nodes, bypassing firewalls and other network security measures configured for load balancers within a cluster. This creates a direct method of communication between the cluster and the outside world, which could be used for more malicious behavior and certainly widens the attack surface of your cluster.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types)
* [https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport](https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport)
* [https://www.tigera.io/blog/new-vulnerability-exposes-kubernetes-to-man-in-the-middle-attacks-heres-how-to-mitigate/](https://www.tigera.io/blog/new-vulnerability-exposes-kubernetes-to-man-in-the-middle-attacks-heres-how-to-mitigate/)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1963]



## Rule query [_rule_query_2248]

```js
kubernetes.audit.objectRef.resource:"services" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.type:"NodePort"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)



