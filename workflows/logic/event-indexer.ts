/**
 * @file event-indexer.ts
 * @notice WS-10 — EventIndexer: Indexes and queries on-chain events from
 *         SentinelActions, ComplianceVault, and CrossChainRelay for the
 *         Operator Dashboard.
 *
 * Spec References:
 *   ARCHITECTURE.md §6   — Layer 6: Monitoring & Response
 *   SMART_CONTRACTS.md §2 — Event definitions for all core contracts
 *   SECURITY.md §6.1      — Severity Levels: P0–P3 dashboard alert classification
 *
 * Indexed Events:
 *   - SentinelActions:  ActionExecuted, ActionLifted, EmergencyPause
 *   - ComplianceVault:  ReportStored
 *   - CrossChainRelay:  AlertSent, AlertReceived, AlertExecuted
 */

import { BaseContract, EventLog, Log } from "ethers";

/** Normalized event record for dashboard consumption */
export interface IndexedEvent {
    eventName: string;
    blockNumber: number;
    transactionHash: string;
    args: Record<string, any>;
}

/** Filter options for querying events */
export interface EventFilter {
    fromBlock?: number;
    toBlock?: number;
    reportType?: number;
    protocol?: string;
    offset?: number;
    limit?: number;
}

/** Aggregated event summary for dashboard header */
export interface EventSummary {
    sentinelEvents: number;
    complianceEvents: number;
    relayEvents: number;
    totalEvents: number;
}

/**
 * EventIndexer — Consumes on-chain events from the three core event-emitting
 * contracts (SentinelActions, ComplianceVault, CrossChainRelay) and provides
 * filtered, paginated, and aggregated queries for the Operator Dashboard.
 *
 * Does NOT require a separate database — queries contract logs directly via
 * ethers.js queryFilter(). Production deployments should cache results.
 */
export class EventIndexer {
    constructor(
        private readonly sentinel: BaseContract,
        private readonly vault: BaseContract,
        private readonly relay: BaseContract,
    ) {}

    /**
     * Retrieve sentinel events (ActionExecuted, ActionLifted, EmergencyPause)
     */
    async getSentinelEvents(filter?: EventFilter): Promise<IndexedEvent[]> {
        const events: IndexedEvent[] = [];
        const fromBlock = filter?.fromBlock ?? 0;
        const toBlock = filter?.toBlock ?? "latest";

        for (const eventName of ["ActionExecuted", "ActionLifted", "EmergencyPause"]) {
            try {
                const raw = await this.sentinel.queryFilter(
                    this.sentinel.filters[eventName]!(),
                    fromBlock,
                    toBlock,
                );
                events.push(...raw.map(e => this.normalize(eventName, e)));
            } catch {
                // Event may not exist on contract — skip silently
            }
        }

        return this.applyPagination(events, filter);
    }

    /**
     * Retrieve compliance events (ReportStored) with optional reportType filter
     */
    async getComplianceEvents(filter?: EventFilter): Promise<IndexedEvent[]> {
        const fromBlock = filter?.fromBlock ?? 0;
        const toBlock = filter?.toBlock ?? "latest";

        const raw = await this.vault.queryFilter(
            this.vault.filters["ReportStored"]!(),
            fromBlock,
            toBlock,
        );

        let events = raw.map(e => this.normalize("ReportStored", e));

        // Filter by reportType if specified
        if (filter?.reportType !== undefined) {
            events = events.filter(e => Number(e.args.reportType) === filter.reportType);
        }

        return this.applyPagination(events, filter);
    }

    /**
     * Retrieve relay events (AlertSent, AlertReceived, AlertExecuted)
     */
    async getRelayEvents(filter?: EventFilter): Promise<IndexedEvent[]> {
        const events: IndexedEvent[] = [];
        const fromBlock = filter?.fromBlock ?? 0;
        const toBlock = filter?.toBlock ?? "latest";

        for (const eventName of ["AlertSent", "AlertReceived", "AlertExecuted"]) {
            try {
                const raw = await this.relay.queryFilter(
                    this.relay.filters[eventName]!(),
                    fromBlock,
                    toBlock,
                );
                events.push(...raw.map(e => this.normalize(eventName, e)));
            } catch {
                // Event may not exist on contract — skip silently
            }
        }

        return this.applyPagination(events, filter);
    }

    /**
     * Dashboard summary — aggregate event counts by category
     */
    async getEventSummary(): Promise<EventSummary> {
        const [sentinel, compliance, relay] = await Promise.all([
            this.getSentinelEvents(),
            this.getComplianceEvents(),
            this.getRelayEvents(),
        ]);

        return {
            sentinelEvents: sentinel.length,
            complianceEvents: compliance.length,
            relayEvents: relay.length,
            totalEvents: sentinel.length + compliance.length + relay.length,
        };
    }

    // ── Internal Helpers ─────────────────────────────────────────────────

    /**
     * Normalize a raw ethers event log into a dashboard-friendly IndexedEvent.
     * Handles both EventLog (decoded) and Log (raw) formats.
     */
    private normalize(eventName: string, raw: EventLog | Log): IndexedEvent {
        const args: Record<string, any> = {};

        if (raw instanceof EventLog && raw.args) {
            // Decoded event — copy named arguments
            const fragment = raw.fragment;
            if (fragment && fragment.inputs) {
                fragment.inputs.forEach((input, i) => {
                    args[input.name] = raw.args[i];
                });
            }
        }

        return {
            eventName,
            blockNumber: raw.blockNumber,
            transactionHash: raw.transactionHash,
            args,
        };
    }

    /**
     * Apply offset/limit pagination to an event array.
     */
    private applyPagination(events: IndexedEvent[], filter?: EventFilter): IndexedEvent[] {
        if (!filter) return events;

        const offset = filter.offset ?? 0;
        const limit = filter.limit ?? events.length;
        return events.slice(offset, offset + limit);
    }
}
