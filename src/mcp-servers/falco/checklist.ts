import { SecurityChecklist, SecurityCheck } from '@core/types';

export const FALCO_SECURITY_CHECKLISTS: Record<string, SecurityChecklist> = {
  filesystem: {
    category: "File System Security",
    score: 0,
    status: "unknown",
    checks: [
      {
        id: "write_below_etc",
        name: "Write Below /etc Directory",
        description: "Detect write attempts below /etc directory",
        status: "unknown",
        rule: "Write below etc",
        details: "Monitors for unauthorized modifications to system configuration files in /etc"
      },
      {
        id: "write_below_usr",
        name: "Write Below /usr Directory", 
        description: "Detect write attempts below /usr directory",
        status: "unknown",
        rule: "Write below usr",
        details: "Monitors for unauthorized modifications to system binaries and libraries in /usr"
      },
      {
        id: "create_sensitive_mount",
        name: "Create Sensitive Mount",
        description: "Detect creation of sensitive mount points",
        status: "unknown",
        rule: "Create Sensitive Mount",
        details: "Monitors for mounting of sensitive filesystems that could expose host resources"
      },
      {
        id: "modify_binary_dirs",
        name: "Modify Binary Directories",
        description: "Detect modifications to binary directories",
        status: "unknown",
        rule: "Modify Binary Dirs",
        details: "Monitors for unauthorized changes to critical system binary directories"
      },
      {
        id: "write_rpm_database",
        name: "RPM Database Modifications",
        description: "Detect RPM database modifications",
        status: "unknown",
        rule: "Write RPM Database",
        details: "Monitors for unauthorized changes to the RPM package database"
      },
      {
        id: "modify_shell_config",
        name: "Shell Configuration Changes",
        description: "Detect shell configuration file changes",
        status: "unknown",
        rule: "Modify Shell Configuration Files",
        details: "Monitors for changes to shell configuration files like .bashrc, .profile"
      },
      {
        id: "read_sensitive_file",
        name: "Access Sensitive Files",
        description: "Detect access to sensitive files (/etc/shadow, /etc/passwd)",
        status: "unknown",
        rule: "Read sensitive file",
        details: "Monitors unauthorized access to sensitive system files containing credentials"
      }
    ]
  },

  process: {
    category: "Process and Execution Security",
    score: 0,
    status: "unknown",
    checks: [
      {
        id: "spawned_process_in_container",
        name: "Process Spawning in Container",
        description: "Detect process spawning within containers",
        status: "unknown",
        rule: "Process spawned in container",
        details: "Monitors for unexpected process execution within container environments"
      },
      {
        id: "container_shell_spawned",
        name: "Container Shell Execution",
        description: "Detect shell execution in containers",
        status: "unknown",
        rule: "Terminal shell in container",
        details: "Monitors for shell access attempts within containers which may indicate compromise"
      },
      {
        id: "terminal_shell_in_container",
        name: "Terminal Shell in Container",
        description: "Detect terminal shell in containers",
        status: "unknown",
        rule: "Terminal shell in container",
        details: "Monitors for interactive shell sessions within containers"
      },
      {
        id: "privileged_container_started",
        name: "Privileged Container Launch",
        description: "Detect privileged container launches",
        status: "unknown",
        rule: "Launch Privileged Container",
        details: "Monitors for containers started with privileged access to host resources"
      },
      {
        id: "sensitive_process_spawned",
        name: "Sensitive Tool Execution",
        description: "Detect execution of sensitive tools (tcpdump, nmap)",
        status: "unknown",
        rule: "Launch Suspicious Network Tool",
        details: "Monitors for execution of network reconnaissance and monitoring tools"
      },
      {
        id: "recon_commands",
        name: "Reconnaissance Commands",
        description: "Detect reconnaissance command execution (whoami, id, ps)",
        status: "unknown",
        rule: "System procs network activity",
        details: "Monitors for commands commonly used in system reconnaissance"
      },
      {
        id: "binary_executed_from_tmp",
        name: "Binary Execution from /tmp",
        description: "Detect binary execution from /tmp directory",
        status: "unknown",
        rule: "Execute from tmp",
        details: "Monitors for execution of binaries from temporary directories"
      }
    ]
  },

  network: {
    category: "Network Security",
    score: 0,
    status: "unknown", 
    checks: [
      {
        id: "unexpected_network_connection",
        name: "Unexpected Network Connections",
        description: "Detect unexpected outbound connections",
        status: "unknown",
        rule: "Unexpected network connection",
        details: "Monitors for network connections that don't match expected communication patterns"
      },
      {
        id: "unexpected_udp_traffic",
        name: "Anomalous UDP Traffic",
        description: "Detect anomalous UDP traffic patterns",
        status: "unknown",
        rule: "Unexpected UDP traffic",
        details: "Monitors for unusual UDP traffic that may indicate tunneling or covert channels"
      },
      {
        id: "outbound_connection_to_c2",
        name: "C2 Server Connections",
        description: "Detect potential C2 server connections",
        status: "unknown",
        rule: "Outbound or Inbound Internet Connection",
        details: "Monitors for connections to known or suspected command and control servers"
      },
      {
        id: "crypto_mining_pool_connection",
        name: "Crypto Mining Pool Connections",
        description: "Detect cryptocurrency mining pool connections",
        status: "unknown",
        rule: "Detect crypto mining",
        details: "Monitors for connections to known cryptocurrency mining pools"
      },
      {
        id: "suspicious_dns_query",
        name: "Suspicious DNS Queries",
        description: "Detect suspicious DNS queries",
        status: "unknown",
        rule: "Detect DNS queries",
        details: "Monitors for DNS queries to suspicious or malicious domains"
      },
      {
        id: "port_scanning_detected",
        name: "Port Scanning Activity",
        description: "Detect port scanning activities",
        status: "unknown",
        rule: "Network scan detected",
        details: "Monitors for port scanning activities that may indicate reconnaissance"
      },
      {
        id: "data_exfiltration_attempt",
        name: "Data Exfiltration",
        description: "Detect large data transfers to external IPs",
        status: "unknown",
        rule: "Detect data exfiltration",
        details: "Monitors for large outbound data transfers that may indicate data theft"
      }
    ]
  },

  privilege: {
    category: "Privilege Escalation",
    score: 0,
    status: "unknown",
    checks: [
      {
        id: "sudo_without_tty",
        name: "Sudo Without TTY",
        description: "Detect sudo execution without TTY",
        status: "unknown",
        rule: "Sudo without tty",
        details: "Monitors for sudo commands executed without a terminal, which may indicate automation or compromise"
      },
      {
        id: "setuid_setgid",
        name: "SetUID/SetGID Execution",
        description: "Detect SetUID/SetGID program execution",
        status: "unknown",
        rule: "Set setuid or setgid bit",
        details: "Monitors for execution of programs with elevated privilege bits"
      },
      {
        id: "privilege_escalation_attempt",
        name: "Privilege Escalation Attempts",
        description: "Detect direct privilege escalation attempts",
        status: "unknown",
        rule: "Privilege escalation attempt",
        details: "Monitors for various techniques used to escalate privileges on the system"
      },
      {
        id: "kernel_module_loaded",
        name: "Kernel Module Loading",
        description: "Detect kernel module loading",
        status: "unknown",
        rule: "Load kernel module",
        details: "Monitors for loading of kernel modules which can provide root-level access"
      },
      {
        id: "bpf_program_attached",
        name: "BPF Program Attachment",
        description: "Detect BPF program attachment",
        status: "unknown",
        rule: "Attach to BPF program",
        details: "Monitors for attachment of eBPF programs which can modify kernel behavior"
      },
      {
        id: "capability_abuse",
        name: "Linux Capability Abuse",
        description: "Detect Linux capability abuse",
        status: "unknown",
        rule: "Detect capability abuse",
        details: "Monitors for misuse of Linux capabilities to gain elevated privileges"
      }
    ]
  },

  container: {
    category: "Container Security",
    score: 0,
    status: "unknown",
    checks: [
      {
        id: "container_drift",
        name: "Container Drift",
        description: "Detect deviation from original container image",
        status: "unknown",
        rule: "Container drift detected",
        details: "Monitors for changes to running containers that differ from the original image"
      },
      {
        id: "container_escape_attempt",
        name: "Container Escape Attempts",
        description: "Detect container escape attempts",
        status: "unknown",
        rule: "Container escape",
        details: "Monitors for attempts to break out of container isolation"
      },
      {
        id: "docker_socket_mount",
        name: "Docker Socket Mounting",
        description: "Detect Docker socket mounting",
        status: "unknown",
        rule: "Docker socket mounted",
        details: "Monitors for containers with access to the Docker socket"
      },
      {
        id: "host_namespace_enter",
        name: "Host Namespace Entry",
        description: "Detect host namespace entry",
        status: "unknown",
        rule: "Container enters host namespace",
        details: "Monitors for containers entering host namespaces"
      },
      {
        id: "privileged_pod_created",
        name: "Privileged Pod Creation",
        description: "Detect privileged pod creation",
        status: "unknown",
        rule: "Privileged pod created",
        details: "Monitors for creation of pods with privileged security context"
      },
      {
        id: "host_pid_namespace_used",
        name: "Host PID Namespace Usage",
        description: "Detect host PID namespace usage",
        status: "unknown",
        rule: "Host PID namespace used",
        details: "Monitors for containers using host PID namespace"
      },
      {
        id: "host_network_namespace_used",
        name: "Host Network Namespace Usage",
        description: "Detect host network namespace usage",
        status: "unknown",
        rule: "Host network namespace used",
        details: "Monitors for containers using host network namespace"
      }
    ]
  },

  kubernetes: {
    category: "Kubernetes-Specific Security",
    score: 0,
    status: "unknown",
    checks: [
      {
        id: "k8s_api_connection",
        name: "Unauthorized K8s API Access",
        description: "Detect unauthorized K8s API access",
        status: "unknown",
        rule: "Contact kubernetes API server",
        details: "Monitors for unauthorized access to Kubernetes API server"
      },
      {
        id: "service_account_token_access",
        name: "Service Account Token Access",
        description: "Detect service account token access",
        status: "unknown",
        rule: "Service account token access",
        details: "Monitors for access to Kubernetes service account tokens"
      },
      {
        id: "configmap_secret_access",
        name: "ConfigMap/Secret Access",
        description: "Detect ConfigMap/Secret access patterns",
        status: "unknown",
        rule: "ConfigMap or Secret access",
        details: "Monitors for access to Kubernetes ConfigMaps and Secrets"
      },
      {
        id: "pod_exec_attach",
        name: "Pod Exec/Attach Commands",
        description: "Detect pod exec/attach commands",
        status: "unknown",
        rule: "Pod exec or attach",
        details: "Monitors for kubectl exec or attach commands to pods"
      },
      {
        id: "namespace_change",
        name: "Namespace Modifications",
        description: "Detect namespace modification attempts",
        status: "unknown",
        rule: "Namespace modification",
        details: "Monitors for changes to Kubernetes namespaces"
      },
      {
        id: "rbac_violation",
        name: "RBAC Policy Violations",
        description: "Detect RBAC policy violations",
        status: "unknown",
        rule: "RBAC violation",
        details: "Monitors for violations of Kubernetes RBAC policies"
      },
      {
        id: "admission_controller_bypass",
        name: "Admission Controller Bypass",
        description: "Detect admission controller bypass attempts",
        status: "unknown",
        rule: "Admission controller bypass",
        details: "Monitors for attempts to bypass Kubernetes admission controllers"
      }
    ]
  }
};

export function calculateChecklistScore(checklist: SecurityChecklist): number {
  const totalChecks = checklist.checks.length;
  if (totalChecks === 0) return 0;

  let score = 0;
  for (const check of checklist.checks) {
    switch (check.status) {
      case 'pass':
        score += 100;
        break;
      case 'warning':
        score += 70;
        break;
      case 'fail':
        score += 0;
        break;
      case 'unknown':
        score += 50; // Neutral score for unknown status
        break;
    }
  }

  return Math.round(score / totalChecks);
}

export function updateChecklistStatus(checklist: SecurityChecklist): void {
  const failedChecks = checklist.checks.filter(check => check.status === 'fail').length;
  const warningChecks = checklist.checks.filter(check => check.status === 'warning').length;
  const totalChecks = checklist.checks.length;

  if (failedChecks === 0 && warningChecks === 0) {
    checklist.status = 'passing';
  } else if (failedChecks > totalChecks * 0.3) {
    checklist.status = 'failing';
  } else {
    checklist.status = 'warning';
  }

  checklist.score = calculateChecklistScore(checklist);
}

export function getAllSecurityChecks(): SecurityCheck[] {
  const allChecks: SecurityCheck[] = [];
  
  for (const checklist of Object.values(FALCO_SECURITY_CHECKLISTS)) {
    allChecks.push(...checklist.checks);
  }
  
  return allChecks;
}

export function getCheckByRule(ruleName: string): SecurityCheck | undefined {
  const allChecks = getAllSecurityChecks();
  return allChecks.find(check => 
    check.rule && check.rule.toLowerCase() === ruleName.toLowerCase()
  );
}