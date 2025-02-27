---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-kubernetes-container-created-with-excessive-linux-capabilities.html
---

# Kubernetes Container Created with Excessive Linux Capabilities [prebuilt-rule-8-4-2-kubernetes-container-created-with-excessive-linux-capabilities]

This rule detects a container deployed with one or more dangerously permissive Linux capabilities. An attacker with the ability to deploy a container with added capabilities could use this for further execution, lateral movement, or privilege escalation within a cluster. The capabilities detected in this rule have been used in container escapes to the host machine.

**Rule type**: query

**Rule indices**:

* logs-kubernetes.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities)
* [https://man7.org/linux/man-pages/man7/capabilities.7.html](https://man7.org/linux/man-pages/man7/capabilities.7.md)
* [https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)

**Tags**:

* Elastic
* Kubernetes
* Continuous Monitoring
* Execution
* Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3282]

## Triage and analysis

## Investigating Kubernetes Container Created with Excessive Linux Capabilities

Linux capabilities were designed to divide root privileges into smaller units. Each capability grants a thread just enough power to perform specific privileged tasks. In Kubernetes, containers are given a set of default capabilities that can be dropped or added to at the time of creation. Added capabilities entitle containers in a pod with additional privileges that can be used to change
core processes, change network settings of a cluster, or directly access the underlying host. The following have been used in container escape techniques:

BPF - Allow creating BPF maps, loading BPF Type Format (BTF) data, retrieve JITed code of BPF programs, and more.
DAC_READ_SEARCH - Bypass file read permission checks and directory read and execute permission checks.
NET_ADMIN - Perform various network-related operations.
SYS_ADMIN - Perform a range of system administration operations.
SYS_BOOT - Use reboot(2) and kexec_load(2), reboot and load a new kernel for later execution.
SYS_MODULE - Load and unload kernel modules.
SYS_PTRACE - Trace arbitrary processes using ptrace(2).
SYS_RAWIO - Perform I/O port operations (iopl(2) and ioperm(2)).
SYSLOG - Perform privileged syslog(2) operations.

## False positive analysis

- While these capabilities are not included by default in containers, some legitimate images may need to add them. This rule leaves space for the exception of trusted container images. To add an exception, add the trusted container image name to the query field, kubernetes.audit.requestObject.spec.containers.image.

## Rule query [_rule_query_3846]

```js
event.dataset: kubernetes.audit_logs
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb: create
  and kubernetes.audit.objectRef.resource: pods
  and kubernetes.audit.requestObject.spec.containers.securityContext.capabilities.add: ("BPF" or "DAC_READ_SEARCH"  or "NET_ADMIN" or "SYS_ADMIN" or "SYS_BOOT" or "SYS_MODULE" or "SYS_PTRACE" or "SYS_RAWIO"  or "SYSLOG")
  and not kubernetes.audit.requestObject.spec.containers.image : ("docker.elastic.co/beats/elastic-agent:8.4.0" or "rancher/klipper-lb:v0.3.5" or "")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Deploy Container
    * ID: T1610
    * Reference URL: [https://attack.mitre.org/techniques/T1610/](https://attack.mitre.org/techniques/T1610/)



