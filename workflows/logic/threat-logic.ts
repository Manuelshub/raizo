import { TelemetryFrame, ThreatAssessment, RecommendedAction } from "./types";

export * from "./types";

export const SYSTEM_PROMPT = `
You are Raizo Sentinel, an autonomous DeFi security analyst. You analyze
on-chain telemetry and threat intelligence to predict exploits.

RULES:
1. Output ONLY valid JSON matching the ThreatAssessment schema.
2. Do NOT hallucinate data — if uncertain, assign lower confidence scores.
3. A confidence score above 0.85 triggers protective action.
4. Always cite evidence from the telemetry frame.
5. Exploit taxonomy: flash_loan, reentrancy, access_control, oracle_manipulation, logic_error, governance_attack.
`;

const ACTION_THRESHOLDS: {
  min: number;
  max: number;
  action: RecommendedAction;
}[] = [
  { min: 0.0, max: 0.49, action: "NONE" },
  { min: 0.5, max: 0.69, action: "ALERT" },
  { min: 0.7, max: 0.84, action: "RATE_LIMIT" },
  { min: 0.85, max: 0.94, action: "DRAIN_BLOCK" },
  { min: 0.95, max: 1.0, action: "PAUSE" },
];

export function escalateAction(riskScore: number): RecommendedAction {
  const clamped = Math.max(0, Math.min(1, riskScore));
  for (const band of ACTION_THRESHOLDS) {
    if (clamped >= band.min && clamped <= band.max) return band.action;
  }
  return "NONE";
}

interface HeuristicWeights {
  tvlDrop1h: number;
  tvlDrop24h: number;
  flashLoanActivity: number;
  failedTxRatio: number;
  priceDeviation: number;
  mempoolAnomalies: number;
  threatIntelSignals: number;
  contractStateRisk: number;
}

const DEFAULT_WEIGHTS: HeuristicWeights = {
  tvlDrop1h: 0.2,
  tvlDrop24h: 0.1,
  flashLoanActivity: 0.2,
  failedTxRatio: 0.1,
  priceDeviation: 0.15,
  mempoolAnomalies: 0.1,
  threatIntelSignals: 0.1,
  contractStateRisk: 0.05,
};

export class HeuristicAnalyzer {
  private weights: HeuristicWeights;

  constructor(weights: Partial<HeuristicWeights> = {}) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
  }

  score(telemetry: TelemetryFrame): {
    baseRiskScore: number;
    citations: string[];
  } {
    const citations: string[] = [];
    let weightedSum = 0;

    const tvl1h = this.normalize(
      Math.abs(Math.min(0, telemetry.tvl.delta1h)),
      0,
      30,
    );
    if (tvl1h > 0) citations.push("tvl.delta1h");
    weightedSum += tvl1h * this.weights.tvlDrop1h;

    const tvl24h = this.normalize(
      Math.abs(Math.min(0, telemetry.tvl.delta24h)),
      0,
      50,
    );
    if (tvl24h > 0) citations.push("tvl.delta24h");
    weightedSum += tvl24h * this.weights.tvlDrop24h;

    const flash = this.normalize(
      telemetry.mempoolSignals.flashLoanBorrows,
      0,
      5,
    );
    if (flash > 0) citations.push("mempoolSignals.flashLoanBorrows");
    weightedSum += flash * this.weights.flashLoanActivity;

    const failedTx = this.normalize(
      telemetry.transactionMetrics.failedTxRatio,
      0,
      0.3,
    );
    if (failedTx > 0) citations.push("transactionMetrics.failedTxRatio");
    weightedSum += failedTx * this.weights.failedTxRatio;

    const priceDev = this.normalize(
      Math.abs(telemetry.priceData.priceDeviation),
      0,
      15,
    );
    if (priceDev > 0) citations.push("priceData.priceDeviation");
    weightedSum += priceDev * this.weights.priceDeviation;

    const mempoolScore = this.normalize(
      telemetry.mempoolSignals.pendingLargeWithdrawals +
        telemetry.mempoolSignals.suspiciousCalldata.length,
      0,
      20,
    );
    if (mempoolScore > 0)
      citations.push("mempoolSignals.pendingLargeWithdrawals");
    weightedSum += mempoolScore * this.weights.mempoolAnomalies;

    const threatScore = this.normalize(
      telemetry.threatIntel.activeCVEs.length * 3 +
        telemetry.threatIntel.darkWebMentions +
        Math.max(0, -telemetry.threatIntel.socialSentiment) * 5,
      0,
      20,
    );
    if (threatScore > 0) citations.push("threatIntel.activeCVEs");
    weightedSum += threatScore * this.weights.threatIntelSignals;

    const stateRisk =
      (telemetry.contractState.pendingUpgrade ? 0.4 : 0) +
      this.normalize(telemetry.contractState.unusualApprovals, 0, 10) * 0.6;
    if (stateRisk > 0) citations.push("contractState.pendingUpgrade");
    weightedSum += stateRisk * this.weights.contractStateRisk;

    return {
      baseRiskScore: Math.min(1, weightedSum),
      citations,
    };
  }

  private normalize(value: number, min: number, max: number): number {
    if (max === min) return 0;
    return Math.max(0, Math.min(1, (value - min) / (max - min)));
  }
}

const SEVERITY_MAP: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export function mapSeverity(
  riskScore: number,
  threatCategory?: string,
): number {
  if (riskScore >= 0.95) return 3; // CRITICAL
  if (riskScore >= 0.85) return 2; // HIGH
  if (riskScore >= 0.7) return 1; // MEDIUM
  return 0; // LOW
}

export function mapSeverityFromPattern(severity: string): number {
  return SEVERITY_MAP[severity] ?? 2;
}

const ACTION_ENUM: Record<string, number> = {
  PAUSE: 0,
  RATE_LIMIT: 1,
  DRAIN_BLOCK: 2,
  ALERT: 3,
  CUSTOM: 4,
};

export function buildThreatReport(
  agentId: string,
  protocol: string,
  assessment: ThreatAssessment,
  heuristicCitations: string[],
): {
  reportId: string;
  agentId: string;
  targetProtocol: string;
  action: number;
  severity: number;
  confidenceScore: number;
  evidenceHash: string;
  timestamp: number;
} {
  const allCitations = [
    ...new Set([...heuristicCitations, ...assessment.evidenceCitations]),
  ];
  const primaryThreat = assessment.threats[0];

  const ts = Math.floor(Date.now() / 1000);
  const reportIdInput = `${agentId}-${protocol}-${ts}`;
  let reportId = "0x";
  for (let i = 0; i < reportIdInput.length; i++) {
    reportId += reportIdInput.charCodeAt(i).toString(16).padStart(2, "0");
  }

  return {
    reportId,
    agentId,
    targetProtocol: protocol,
    action: ACTION_ENUM[assessment.recommendedAction] ?? 3,
    severity: primaryThreat
      ? mapSeverityFromPattern(primaryThreat.category)
      : mapSeverity(assessment.overallRiskScore),
    confidenceScore: Math.floor(assessment.overallRiskScore * 10000),
    evidenceHash: JSON.stringify(allCitations),
    timestamp: ts,
  };
}

export const HEURISTIC_GATE_THRESHOLD = 0.3;

export function runSentinelPipeline(
  agentId: string,
  targetProtocol: string,
  telemetry: TelemetryFrame,
  llmAssessment: ThreatAssessment | null,
): ReturnType<typeof buildThreatReport> | null {
  const heuristic = new HeuristicAnalyzer();
  const { baseRiskScore, citations: heuristicCitations } =
    heuristic.score(telemetry);

  if (baseRiskScore < HEURISTIC_GATE_THRESHOLD) {
    return null;
  }

  if (!llmAssessment) {
    return null;
  }

  if (llmAssessment.threatDetected && llmAssessment.overallRiskScore >= 0.5) {
    const escalatedAction = escalateAction(llmAssessment.overallRiskScore);
    const finalAssessment: ThreatAssessment = {
      ...llmAssessment,
      recommendedAction: escalatedAction,
    };

    return buildThreatReport(
      agentId,
      targetProtocol,
      finalAssessment,
      heuristicCitations,
    );
  }

  return null;
}
