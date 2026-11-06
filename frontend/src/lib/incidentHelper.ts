import type { Alert, Agent, NormalizedEvent } from "../types";
import { shortId } from "./format";

export function formatResource(res?: string | null): string {
  if (!res) return "restricted data";
  if (res.includes("customer_pii")) return "Customer PII";
  if (res.includes("paste-site")) return "paste-site";
  if (res.includes("approved-partner")) return "partner API";
  const base = res.split("/").pop()?.split(":").pop() ?? res;
  return base.replace(/_/g, " ");
}

export function getAgentRole(agentId: string, agents: Agent[], events?: NormalizedEvent[]): string {
  const ag = agents.find((a) => a.agent_id === agentId);
  if (ag?.role) return ag.role;
  if (events) {
    const ev = events.find((e) => e.agent_id === agentId);
    if (ev?.agent_role) return ev.agent_role;
  }
  return shortId(agentId);
}

export function deriveIncidentTitle(alert: Alert, agents: Agent[], events?: NormalizedEvent[]): string {
  const roles = alert.agent_ids.map((id) => getAgentRole(id, agents, events));
  const uniqueRoles = Array.from(new Set(roles));
  const rolesStr = uniqueRoles.join(" & ");
  const res = formatResource(alert.resource);

  switch (alert.rule_id) {
    case "SG-001":
      return `Unauthorized read of ${res} by ${rolesStr}`;
    case "SG-002":
      return `${res} sent to external destination by ${rolesStr}`;
    case "SG-003":
      return `${res} sent to paste-site via ${rolesStr}`;
    case "SG-004":
      return `Anomalous behavior diverging from baseline by ${rolesStr}`;
    case "SG-005":
      return `Hidden dead-drop exfiltration in ${res} by ${rolesStr}`;
    case "SG-006":
      return `Monitoring evasion or shutdown resistance by ${rolesStr}`;
    case "SG-007":
      return `Unauthorized self-replication attempt by ${rolesStr}`;
    case "SG-008":
      return `Privilege escalation attempt by ${rolesStr}`;
    case "SG-009":
      return `Honeytoken tripwire triggered on ${res} by ${rolesStr}`;
    case "SG-010":
      return `Missing or tampered telemetry log detected for ${rolesStr}`;
    case "SG-011":
      return `Compute power seeking or budget exhaustion by ${rolesStr}`;
    case "SG-012":
      return `Prompt injection or hijacked memory detected in ${rolesStr}`;
    case "SG-013":
      return `Cascading execution failure across ${rolesStr}`;
    case "SG-014":
      return `Deceptive reporting (action mismatch) by ${rolesStr}`;
    case "SG-015":
      return `Reward hacking or test tampering detected by ${rolesStr}`;
    case "SG-016":
      return `Slow salami-style exfiltration of ${res} by ${rolesStr}`;
    case "SG-017":
      return `Coercive human manipulation detected from ${rolesStr}`;
    case "SG-018":
      return `Infinite execution loop detected in ${rolesStr}`;
    case "SG-019":
      return `Untrusted supply chain tool execution by ${rolesStr}`;
    case "SG-020":
      return `Steganographic hidden channel detected in ${rolesStr}`;
    default:
      if (alert.reason && alert.reason.length < 75) return alert.reason;
      return `${alert.rule_name} by ${rolesStr}`;
  }
}
