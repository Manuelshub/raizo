import {
  ThreatEvent,
  ProtocolDeployment,
  PropagationScope,
  PropagationMessage,
} from "./types";

export * from "./types";

export function evaluateScope(
  event: ThreatEvent,
  deployment: ProtocolDeployment,
): PropagationScope {
  if (event.severity === 3) {
    return "ALL_CHAINS";
  }

  if (deployment.chains.length > 1) {
    return "SAME_PROTOCOL";
  }

  if (deployment.relatedProtocols && deployment.relatedProtocols.length > 0) {
    return "RELATED_ALERT";
  }

  return "LOCAL_ONLY";
}

export function resolveTargetChains(
  event: ThreatEvent,
  scope: PropagationScope,
  monitoredChains: number[],
): number[] {
  switch (scope) {
    case "ALL_CHAINS":
    case "SAME_PROTOCOL":
    case "RELATED_ALERT":
      return monitoredChains.filter((c) => c !== event.sourceChain);
    case "LOCAL_ONLY":
    default:
      return [];
  }
}

export function buildPropagationMessages(
  event: ThreatEvent,
  scope: PropagationScope,
  monitoredChains: number[],
): PropagationMessage[] {
  const targetChains = resolveTargetChains(event, scope, monitoredChains);

  return targetChains.map((destChain) => ({
    destChain,
    reportId: event.reportId,
    targetProtocol: event.targetProtocol,
    action: scope === "RELATED_ALERT" ? 3 : event.action,
    severity: event.severity,
  }));
}

export function runCoordinatorPipeline(
  event: ThreatEvent,
  deployment: ProtocolDeployment,
  monitoredChains: number[],
): PropagationMessage[] {
  const scope = evaluateScope(event, deployment);
  return buildPropagationMessages(event, scope, monitoredChains);
}

export function parseThreatReportedEvent(eventData: any): ThreatEvent {
  return {
    reportId: eventData.reportId ?? eventData.topics?.[1] ?? "0x",
    agentId: eventData.agentId ?? eventData.topics?.[2] ?? "0x",
    sourceChain: eventData.sourceChain ?? 1,
    targetProtocol: eventData.targetProtocol ?? eventData.address ?? "0x",
    action: eventData.action ?? 0,
    severity: eventData.severity ?? 0,
    confidenceScore: eventData.confidenceScore ?? 0,
    evidenceHash: eventData.evidenceHash ?? "0x",
    timestamp: eventData.timestamp ?? Math.floor(Date.now() / 1000),
  };
}
