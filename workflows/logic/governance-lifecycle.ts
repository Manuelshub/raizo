/**
 * @file governance-lifecycle.ts
 * @notice WS-10 — GovernanceLifecycleTracker: Tracks GovernanceGate proposal
 *         lifecycle (propose → vote → execute) for the Operator Dashboard.
 *
 * Spec References:
 *   SMART_CONTRACTS.md §2.4 — GovernanceGate interface:
 *     Events: ProposalCreated, VoteCast, ProposalExecuted
 *     Views: getProposal(proposalId), proposalCount()
 *   AI_AGENTS.md §6         — Agent Lifecycle: Governance vote for deactivation
 *   COMPLIANCE.md §5.2      — Rule Update Flow: GovernanceGate World ID vote
 *   SECURITY.md §3.5        — Governance Threats: GOV-1→3 (Sybil, oracle failure, capture)
 */

import { BaseContract, EventLog, Log } from "ethers";

/** Proposal details from on-chain struct */
export interface ProposalDetails {
    proposalId: number;
    descriptionHash: string;
    proposer: string;
    forVotes: number;
    againstVotes: number;
    startBlock: number;
    endBlock: number;
    executed: boolean;
}

/** Vote summary for a proposal */
export interface VoteSummary {
    proposalId: number;
    forVotes: number;
    againstVotes: number;
    totalVotes: number;
}

/** Proposal status assessment */
export interface ProposalStatus {
    proposalId: number;
    passed: boolean;
    executed: boolean;
    expired: boolean;
    votingActive: boolean;
}

/** Lifecycle phases of a proposal */
export interface ProposalLifecycle {
    created: boolean;
    votingActive: boolean;
    executed: boolean;
    expired: boolean;
}

/** Timeline with block numbers */
export interface ProposalTimeline {
    proposalId: number;
    createdAtBlock: number;
    startBlock: number;
    endBlock: number;
    executedAtBlock: number | null;
}

/** Participation metrics */
export interface ParticipationRate {
    totalVotesCast: number;
    totalProposals: number;
    avgVotesPerProposal: number;
}

/**
 * GovernanceLifecycleTracker — Queries GovernanceGate events and state to
 * provide a complete view of proposal lifecycles for the Operator Dashboard.
 *
 * Tracks: proposal creation, voting, execution, expiry, and participation.
 * Enables dashboard views for governance health per SECURITY.md §3.5 GOV-3
 * (governance capture via low participation detection).
 */
export class GovernanceLifecycleTracker {
    constructor(private readonly govGate: BaseContract) {}

    /**
     * Get all proposals by querying ProposalCreated events and enriching
     * with on-chain proposal state.
     */
    async getProposals(): Promise<ProposalDetails[]> {
        const count = Number(await (this.govGate as any).proposalCount());
        const proposals: ProposalDetails[] = [];

        for (let i = 0; i < count; i++) {
            const p = await this.getProposalDetails(i);
            proposals.push(p);
        }

        return proposals;
    }

    /**
     * Get vote summary for a specific proposal.
     */
    async getVoteSummary(proposalId: number): Promise<VoteSummary> {
        const p = await (this.govGate as any).getProposal(proposalId);
        const forVotes = Number(p.forVotes);
        const againstVotes = Number(p.againstVotes);

        return {
            proposalId,
            forVotes,
            againstVotes,
            totalVotes: forVotes + againstVotes,
        };
    }

    /**
     * Assess the current status of a proposal.
     * Considers: vote tally, execution state, block-based expiry.
     */
    async getProposalStatus(proposalId: number): Promise<ProposalStatus> {
        const p = await (this.govGate as any).getProposal(proposalId);
        const currentBlock = await this.govGate.runner!.provider!.getBlockNumber();

        const forVotes = Number(p.forVotes);
        const againstVotes = Number(p.againstVotes);
        const endBlock = Number(p.endBlock);
        const executed = p.executed;
        const expired = currentBlock > endBlock && !executed;
        const votingActive = currentBlock >= Number(p.startBlock) && currentBlock <= endBlock;
        const passed = forVotes > againstVotes;

        return {
            proposalId,
            passed,
            executed,
            expired,
            votingActive,
        };
    }

    /**
     * Get lifecycle phases for a proposal.
     */
    async getProposalLifecycle(proposalId: number): Promise<ProposalLifecycle> {
        const status = await this.getProposalStatus(proposalId);
        const p = await (this.govGate as any).getProposal(proposalId);
        const currentBlock = await this.govGate.runner!.provider!.getBlockNumber();

        return {
            created: true, // If we can read it, it was created
            votingActive: status.votingActive,
            executed: status.executed,
            expired: status.expired,
        };
    }

    /**
     * Get timeline with block numbers for dashboard display.
     */
    async getProposalTimeline(proposalId: number): Promise<ProposalTimeline> {
        const p = await (this.govGate as any).getProposal(proposalId);

        // Find the creation block from ProposalCreated events
        let createdAtBlock = Number(p.startBlock);
        try {
            const events = await this.govGate.queryFilter(
                this.govGate.filters["ProposalCreated"]!(),
            );
            const creationEvent = events.find(e => {
                if (e instanceof EventLog && e.args) {
                    return Number(e.args[0]) === proposalId;
                }
                return false;
            });
            if (creationEvent) {
                createdAtBlock = creationEvent.blockNumber;
            }
        } catch {
            // Fall back to startBlock
        }

        // Find execution block if executed
        let executedAtBlock: number | null = null;
        if (p.executed) {
            try {
                const execEvents = await this.govGate.queryFilter(
                    this.govGate.filters["ProposalExecuted"]!(),
                );
                const execEvent = execEvents.find(e => {
                    if (e instanceof EventLog && e.args) {
                        return Number(e.args[0]) === proposalId;
                    }
                    return false;
                });
                if (execEvent) {
                    executedAtBlock = execEvent.blockNumber;
                }
            } catch {
                // Not executed
            }
        }

        return {
            proposalId,
            createdAtBlock,
            startBlock: Number(p.startBlock),
            endBlock: Number(p.endBlock),
            executedAtBlock,
        };
    }

    /**
     * Get all active proposals (within voting period, not executed/expired).
     */
    async getActiveProposals(): Promise<ProposalDetails[]> {
        const all = await this.getProposals();
        const currentBlock = await this.govGate.runner!.provider!.getBlockNumber();

        return all.filter(p => {
            const withinVotingPeriod = currentBlock <= p.endBlock;
            return !p.executed && withinVotingPeriod;
        });
    }

    /**
     * Compute participation rate across all proposals.
     * Useful for detecting governance capture risk (SECURITY.md §3.5 GOV-3).
     */
    async getParticipationRate(): Promise<ParticipationRate> {
        // Count VoteCast events
        let totalVotesCast = 0;
        try {
            const voteEvents = await this.govGate.queryFilter(
                this.govGate.filters["VoteCast"]!(),
            );
            totalVotesCast = voteEvents.length;
        } catch {
            // No events
        }

        const totalProposals = Number(await (this.govGate as any).proposalCount());
        const avgVotesPerProposal = totalProposals > 0
            ? Math.round((totalVotesCast / totalProposals) * 100) / 100
            : 0;

        return {
            totalVotesCast,
            totalProposals,
            avgVotesPerProposal,
        };
    }

    // ── Internal Helpers ─────────────────────────────────────────────────

    /**
     * Read and normalize a single proposal from on-chain state.
     */
    private async getProposalDetails(proposalId: number): Promise<ProposalDetails> {
        const p = await (this.govGate as any).getProposal(proposalId);

        return {
            proposalId: Number(p.proposalId),
            descriptionHash: p.descriptionHash,
            proposer: p.proposer,
            forVotes: Number(p.forVotes),
            againstVotes: Number(p.againstVotes),
            startBlock: Number(p.startBlock),
            endBlock: Number(p.endBlock),
            executed: p.executed,
        };
    }
}
