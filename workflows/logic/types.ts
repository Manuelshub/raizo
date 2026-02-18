export interface TelemetryFrame {
  chainId: number;
  blockNumber: number;
  tvl: {
    current: bigint;
    delta1h: number;
    delta24h: number;
  };
  transactionMetrics: {
    volumeUSD: bigint;
    uniqueAddresses: number;
    largeTransactions: number;
    failedTxRatio: number;
  };
  contractState: {
    owner: string;
    paused: boolean;
    pendingUpgrade: boolean;
    unusualApprovals: number;
  };
  mempoolSignals: {
    pendingLargeWithdrawals: number;
    flashLoanBorrows: number;
    suspiciousCalldata: string[];
  };
  threatIntel: {
    activeCVEs: string[];
    exploitPatterns: ExploitPattern[];
    darkWebMentions: number;
    socialSentiment: number;
  };
  priceData: {
    tokenPrice: bigint;
    priceDeviation: number;
    oracleLatency: number;
  };
}

export interface ExploitPattern {
  patternId: string;
  category:
    | "flash_loan"
    | "reentrancy"
    | "access_control"
    | "oracle_manipulation"
    | "logic_error"
    | "governance_attack";
  severity: "low" | "medium" | "high" | "critical";
  indicators: string[];
  confidence: number;
}

export interface ThreatAssessment {
  overallRiskScore: number;
  threatDetected: boolean;
  threats: {
    category: string;
    confidence: number;
    indicators: string[];
    estimatedImpactUSD: number;
  }[];
  recommendedAction: "NONE" | "ALERT" | "RATE_LIMIT" | "DRAIN_BLOCK" | "PAUSE";
  reasoning: string;
  evidenceCitations: string[];
}

export type RecommendedAction =
  | "NONE"
  | "ALERT"
  | "RATE_LIMIT"
  | "DRAIN_BLOCK"
  | "PAUSE";

export interface RegulatoryRule {
  ruleId: string;
  framework: "AML" | "MiCA" | "SEC" | "ESG";
  version: string;
  effectiveDate: number;
  condition: {
    metric: string;
    operator: "gt" | "lt" | "eq" | "in" | "matches";
    threshold: number | string | string[];
  };
  action: {
    type: "flag" | "alert" | "block" | "report";
    severity: "info" | "warning" | "violation";
    narrative: string;
  };
  regulatoryReference: string;
  jurisdiction: string[];
}

export interface ComplianceReportFinding {
  ruleId: string;
  severity: "info" | "warning" | "violation";
  narrative: string;
  detectedAt: number;
  evidence: any;
}

export interface ComplianceReport {
  metadata: {
    reportId: string;
    generatedAt: number;
    framework: string;
    coverageChains: number[];
    periodStart: number;
    periodEnd: number;
  };
  findings: ComplianceReportFinding[];
  riskSummary: {
    overallRisk: "low" | "medium" | "high";
    flaggedTransactions: number;
    flaggedAddresses: string[];
    complianceScore: number;
  };
  recommendations: string[];
}

export type PropagationScope =
  | "LOCAL_ONLY"
  | "SAME_PROTOCOL"
  | "RELATED_ALERT"
  | "ALL_CHAINS";

export interface ProtocolDeployment {
  protocol: string;
  chains: number[];
  relatedProtocols?: string[];
}

export interface ThreatEvent {
  reportId: string;
  agentId: string;
  sourceChain: number;
  targetProtocol: string;
  action: number;
  severity: number;
  confidenceScore: number;
  evidenceHash: string;
  timestamp: number;
}

export interface PropagationMessage {
  destChain: number;
  reportId: string;
  targetProtocol: string;
  action: number;
  severity: number;
}
