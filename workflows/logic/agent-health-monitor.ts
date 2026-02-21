/**
 * @file agent-health-monitor.ts
 * @notice WS-10 — AgentHealthMonitor: Reads agent health metrics from
 *         RaizoCore, SentinelActions, and PaymentEscrow for the Operator Dashboard.
 *
 * Spec References:
 *   AI_AGENTS.md §6.2     — Agent Monitoring & Health metrics:
 *     | Metric                    | Source        | Alert Threshold               |
 *     |---------------------------|---------------|-------------------------------|
 *     | Workflow execution count   | CRE metrics   | < expected per epoch → stalled|
 *     | Consensus failure rate     | DON logs      | > 20% divergence → LLM drift |
 *     | Action budget utilization  | RaizoCore     | > 80% → approaching exhaustion|
 *     | Payment wallet balance     | PaymentEscrow | < 24h runway → low funds     |
 *     | Response latency           | CRE metrics   | > 30s → performance degradation|
 *   ARCHITECTURE.md §6     — Layer 6: Monitoring & Response
 *   SECURITY.md §3.4       — Payment System Threats: PAY-3 budget overflow
 */

import { BaseContract } from "ethers";

/** Budget utilization result */
export interface BudgetUtilization {
    dailySpent: number;
    dailyBudget: number;
    utilizationPct: number; // 0–100
}

/** Action budget utilization result */
export interface ActionBudgetUtilization {
    actionsUsed: number;
    actionBudget: number;
    utilizationPct: number; // 0–100
}

/** Wallet runway assessment */
export interface WalletRunway {
    balance: number;      // USDC (6 decimals → whole units)
    dailyBudget: number;  // USDC per day
    runwayDays: number;   // floor(balance / dailyBudget)
    isLow: boolean;       // < 1 day runway per AI_AGENTS.md §6.2
}

/** Full agent health snapshot */
export interface HealthSnapshot {
    agentId: string;
    isActive: boolean;
    budgetUtilization: BudgetUtilization;
    actionBudgetUtilization: ActionBudgetUtilization;
    walletRunway: WalletRunway;
    budgetExhaustionAlert: boolean; // > 80% utilization per AI_AGENTS.md §6.2
}

/**
 * AgentHealthMonitor — Aggregates health metrics for a registered CRE agent
 * from the on-chain contracts (RaizoCore, SentinelActions, PaymentEscrow).
 *
 * Alert thresholds from AI_AGENTS.md §6.2:
 *   - Action budget utilization > 80% → approaching exhaustion
 *   - Wallet balance < 24h runway → low funds alert
 */
export class AgentHealthMonitor {
    constructor(
        private readonly raizoCore: BaseContract,
        private readonly sentinel: BaseContract,
        private readonly escrow: BaseContract,
    ) {}

    /**
     * Read daily USDC budget utilization for an agent.
     * Sources: PaymentEscrow.getWallet(agentId).dailySpent / RaizoCore.getAgent(agentId).dailyBudgetUSDC
     */
    async getBudgetUtilization(agentId: string): Promise<BudgetUtilization> {
        const [agentConfig, wallet] = await Promise.all([
            (this.raizoCore as any).getAgent(agentId),
            (this.escrow as any).getWallet(agentId),
        ]);

        const dailyBudget = Number(agentConfig.dailyBudgetUSDC) / 1e6;
        const dailySpent = Number(wallet.dailySpent) / 1e6;
        const utilizationPct = dailyBudget > 0
            ? Math.min(100, (dailySpent / dailyBudget) * 100)
            : 0;

        return {
            dailySpent,
            dailyBudget,
            utilizationPct: Math.round(utilizationPct * 100) / 100,
        };
    }

    /**
     * Read action budget utilization (actions used this epoch vs max).
     * Sources: SentinelActions.getActionCount(agentId) / RaizoCore.getAgent(agentId).actionBudgetPerEpoch
     */
    async getActionBudgetUtilization(agentId: string): Promise<ActionBudgetUtilization> {
        const [agentConfig, actionCount] = await Promise.all([
            (this.raizoCore as any).getAgent(agentId),
            (this.sentinel as any).getActionCount(agentId),
        ]);

        const actionsUsed = Number(actionCount);
        const actionBudget = Number(agentConfig.actionBudgetPerEpoch);
        const utilizationPct = actionBudget > 0
            ? Math.min(100, (actionsUsed / actionBudget) * 100)
            : 0;

        return {
            actionsUsed,
            actionBudget,
            utilizationPct: Math.round(utilizationPct * 100) / 100,
        };
    }

    /**
     * Compute wallet runway in days.
     * Runway = floor(balance / dailyBudget). Low = < 1 day.
     * Sources: PaymentEscrow.getWallet(agentId).balance, RaizoCore.getAgent(agentId).dailyBudgetUSDC
     */
    async getWalletRunway(agentId: string): Promise<WalletRunway> {
        const [agentConfig, wallet] = await Promise.all([
            (this.raizoCore as any).getAgent(agentId),
            (this.escrow as any).getWallet(agentId),
        ]);

        const balance = Number(wallet.balance) / 1e6;
        const dailyBudget = Number(agentConfig.dailyBudgetUSDC) / 1e6;
        const runwayDays = dailyBudget > 0 ? Math.floor(balance / dailyBudget) : 0;
        const isLow = runwayDays < 1; // AI_AGENTS.md §6.2: < 24h runway → low funds

        return { balance, dailyBudget, runwayDays, isLow };
    }

    /**
     * Full health snapshot — aggregates all metrics for a single agent.
     * Returns safe defaults for inactive/deregistered agents.
     */
    async getHealthSnapshot(agentId: string): Promise<HealthSnapshot> {
        // Check if agent is active
        let isActive = false;
        try {
            const agentConfig = await (this.raizoCore as any).getAgent(agentId);
            isActive = agentConfig.isActive;
        } catch {
            // Agent not registered — treat as inactive
        }

        if (!isActive) {
            return {
                agentId,
                isActive: false,
                budgetUtilization: { dailySpent: 0, dailyBudget: 0, utilizationPct: 0 },
                actionBudgetUtilization: { actionsUsed: 0, actionBudget: 0, utilizationPct: 0 },
                walletRunway: { balance: 0, dailyBudget: 0, runwayDays: 0, isLow: true },
                budgetExhaustionAlert: false,
            };
        }

        const [budgetUtilization, actionBudgetUtilization, walletRunway] = await Promise.all([
            this.getBudgetUtilization(agentId),
            this.getActionBudgetUtilization(agentId),
            this.getWalletRunway(agentId),
        ]);

        // AI_AGENTS.md §6.2: > 80% action budget → approaching exhaustion
        const budgetExhaustionAlert = actionBudgetUtilization.utilizationPct > 80;

        return {
            agentId,
            isActive,
            budgetUtilization,
            actionBudgetUtilization,
            walletRunway,
            budgetExhaustionAlert,
        };
    }
}
