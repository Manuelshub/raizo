/**
 * @file sanctions-client.ts
 * @notice Sanctions list API client for OFAC SDN and EU sanctions integration.
 *
 * Spec References:
 *   COMPLIANCE.md §4    — ACE Pipeline sanctions list integration
 *   AI_AGENTS.md §4.2  — Compliance-Reporter data sources (OFAC, EU)
 *   SECURITY.md §4.2   — Data integrity for external list fetches
 *
 * Architecture:
 *   - Fetches and parses OFAC SDN and EU sanctions lists
 *   - Normalizes all addresses to lowercase for case-insensitive matching
 *   - Deduplicates across OFAC + EU sources
 *   - Caches results with configurable TTL
 *   - Falls back to stale cache on API failure (fail-safe for compliance)
 *   - Throws only when no cached data and API is unavailable
 */

import { SimpleFetch } from "./workflow-helpers";

export interface SanctionsClientConfig {
    ofacUrl: string;
    euUrl: string;
    cacheTtlMs?: number;
}

interface OFACResponse {
    sdnList: Array<{
        addresses: Array<{ address: string }>;
        programs: string[];
    }>;
}

interface EUSanctionsResponse {
    entries: Array<{
        cryptoAddresses: string[];
    }>;
}

export class SanctionsClient {
    private config: SanctionsClientConfig;
    private cachedList: string[] | null = null;
    private cachedAt: number = 0;

    constructor(config: SanctionsClientConfig) {
        this.config = { cacheTtlMs: 300000, ...config }; // Default 5 min cache
    }

    /**
     * Fetches and returns a consolidated, deduplicated, lowercase sanctions address list.
     * Uses cache if within TTL. Falls back to stale cache on API failure.
     */
    async fetchConsolidatedList(fetch: SimpleFetch): Promise<string[]> {
        const now = Date.now();
        const ttl = this.config.cacheTtlMs ?? 300000;

        // Return cached if within TTL
        if (this.cachedList !== null && (now - this.cachedAt) < ttl) {
            return this.cachedList;
        }

        try {
            const [ofacAddresses, euAddresses] = await Promise.all([
                this.fetchOFAC(fetch),
                this.fetchEU(fetch),
            ]);

            // Merge and deduplicate
            const allAddresses = new Set<string>();
            for (const addr of ofacAddresses) {
                allAddresses.add(addr.toLowerCase());
            }
            for (const addr of euAddresses) {
                allAddresses.add(addr.toLowerCase());
            }

            const result = Array.from(allAddresses);
            this.cachedList = result;
            this.cachedAt = now;
            return result;
        } catch (error) {
            // Fall back to stale cache if available
            if (this.cachedList !== null) {
                return this.cachedList;
            }
            throw new Error(`Sanctions list fetch failed and no cached data available: ${error}`);
        }
    }

    /**
     * Checks if an address is on the sanctions list (case-insensitive).
     */
    isAddressSanctioned(list: string[], address: string): boolean {
        return list.includes(address.toLowerCase());
    }

    private async fetchOFAC(fetch: SimpleFetch): Promise<string[]> {
        const res = await fetch(this.config.ofacUrl, { method: "GET" });
        if (!res.ok) throw new Error(`OFAC fetch failed: ${res.status}`);

        const data: OFACResponse = JSON.parse(res.body);
        const addresses: string[] = [];

        for (const entry of data.sdnList) {
            for (const addrObj of entry.addresses) {
                if (addrObj.address) {
                    addresses.push(addrObj.address.toLowerCase());
                }
            }
        }

        return addresses;
    }

    private async fetchEU(fetch: SimpleFetch): Promise<string[]> {
        const res = await fetch(this.config.euUrl, { method: "GET" });
        if (!res.ok) throw new Error(`EU sanctions fetch failed: ${res.status}`);

        const data: EUSanctionsResponse = JSON.parse(res.body);
        const addresses: string[] = [];

        for (const entry of data.entries) {
            for (const addr of entry.cryptoAddresses) {
                if (addr) {
                    addresses.push(addr.toLowerCase());
                }
            }
        }

        return addresses;
    }
}
