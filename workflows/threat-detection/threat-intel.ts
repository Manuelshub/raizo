/**
 * Threat Intelligence Integration Module
 * 
 * Provides off-chain threat intelligence for TelemetryFrame.
 * Per AI_AGENTS.md §3.2, this module populates:
 * - activeCVEs: Known vulnerabilities affecting the protocol
 * - exploitPatterns: Detected attack patterns from threat databases
 * - darkWebMentions: Dark web intelligence mentions
 * - socialSentiment: Social media sentiment analysis (-1.0 to 1.0)
 * 
 * Implementation Strategy:
 * 1. For testnet/MVP: Use free/public APIs with rate limiting
 * 2. For production: Integrate premium threat intelligence services
 */

import type { NodeRuntime } from "@chainlink/cre-sdk";
import { HTTPClient, ok, json, hexToBase64 } from "@chainlink/cre-sdk";
import { stringToHex } from "viem";

// ---------------------------------------------------------------------------
// Interfaces (aligned with AI_AGENTS.md §3.2)
// ---------------------------------------------------------------------------

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

export interface ThreatIntelligence {
  activeCVEs: string[];
  exploitPatterns: ExploitPattern[];
  darkWebMentions: number;
  socialSentiment: number; // -1.0 to 1.0
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// NVD (National Vulnerability Database) API - free, no key required
const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// Immunefi API - for exploit patterns (using public data)
const IMMUNEFI_API_BASE = "https://immunefi.com/api";

// Rate limiting
const REQUEST_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// CVE Database Integration
// ---------------------------------------------------------------------------

/**
 * Fetches active CVEs related to DeFi protocols from NVD.
 * Searches for recent vulnerabilities with keywords: solidity, smart contract, defi
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address (for logging)
 * @returns Array of CVE IDs
 */
export function fetchActiveCVEs(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
): string[] {
  const http = new HTTPClient();

  try {
    nodeRuntime.log(
      `[ThreatIntel] Fetching CVEs for ${protocolAddress}`,
    );

    // Search for recent DeFi-related CVEs
    // Note: NVD API has rate limits (50 requests per 30 seconds without API key)
    const searchParams = new URLSearchParams({
      keywordSearch: "solidity OR smart contract OR defi",
      resultsPerPage: "10",
    });

    const response = http
      .sendRequest(nodeRuntime, {
        url: `${NVD_API_BASE}?${searchParams.toString()}`,
        method: "GET",
      })
      .result();

    if (!ok(response)) {
      nodeRuntime.log(
        `[ThreatIntel] NVD API request failed: ${response.statusCode}`,
      );
      return [];
    }

    const data = json(response) as any;
    const vulnerabilities = data.vulnerabilities || [];

    const cveIds = vulnerabilities
      .slice(0, 5) // Limit to 5 most recent
      .map((vuln: any) => vuln.cve?.id)
      .filter((id: string) => id);

    nodeRuntime.log(
      `[ThreatIntel] Found ${cveIds.length} relevant CVEs`,
    );

    return cveIds;
  } catch (e) {
    nodeRuntime.log(`[ThreatIntel] fetchActiveCVEs error: ${e}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// Exploit Pattern Detection
// ---------------------------------------------------------------------------

/**
 * Fetches known exploit patterns from threat intelligence databases.
 * Uses Immunefi's public bug bounty data and known attack signatures.
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @returns Array of ExploitPattern objects
 */
export function fetchExploitPatterns(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
): ExploitPattern[] {
  nodeRuntime.log(
    `[ThreatIntel] Analyzing exploit patterns for ${protocolAddress}`,
  );

  // For MVP, return baseline patterns based on common DeFi vulnerabilities
  // In production, this would query Immunefi API, Forta alerts, or similar
  const baselinePatterns: ExploitPattern[] = [];

  // Pattern 1: Flash loan attack detection (already handled by indexer)
  // Pattern 2: Reentrancy detection (already handled by indexer)
  // Pattern 3: Access control vulnerabilities (check for ownership changes)
  // Pattern 4: Oracle manipulation (check for price deviations)

  // For now, return empty array - patterns are detected by indexer and heuristics
  // This function is a placeholder for future integration with threat intel APIs

  return baselinePatterns;
}

// ---------------------------------------------------------------------------
// Dark Web Intelligence
// ---------------------------------------------------------------------------

/**
 * Fetches dark web mentions of the protocol from intelligence feeds.
 * 
 * Note: This requires premium threat intelligence services like:
 * - Recorded Future
 * - Flashpoint
 * - Intel 471
 * 
 * For MVP/testnet, returns 0 (no mentions).
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @returns Number of dark web mentions
 */
export function fetchDarkWebMentions(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
): number {
  nodeRuntime.log(
    `[ThreatIntel] Checking dark web mentions for ${protocolAddress}`,
  );

  // MVP: Return 0 (no premium API integration yet)
  // Production: Integrate with Recorded Future or similar service
  // Example API call structure (commented out):
  /*
  const http = new HTTPClient();
  const apiKey = nodeRuntime.getSecret({ id: "DARKWEB_API_KEY" }).result().value;
  
  const response = http.sendRequest(nodeRuntime, {
    url: `https://api.recordedfuture.com/v2/search?entity=${protocolAddress}`,
    method: "GET",
    headers: {
      "X-RFToken": apiKey,
    },
  }).result();
  
  if (ok(response)) {
    const data = json(response) as any;
    return data.mentions?.length || 0;
  }
  */

  return 0;
}

// ---------------------------------------------------------------------------
// Social Sentiment Analysis
// ---------------------------------------------------------------------------

/**
 * Analyzes social media sentiment for the protocol.
 * 
 * Sources:
 * - Twitter/X API for mentions and sentiment
 * - Reddit API for community discussions
 * - Discord/Telegram (if available)
 * 
 * Returns sentiment score from -1.0 (very negative) to 1.0 (very positive).
 * 
 * For MVP/testnet, returns 0.0 (neutral).
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @returns Sentiment score (-1.0 to 1.0)
 */
export function fetchSocialSentiment(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
): number {
  nodeRuntime.log(
    `[ThreatIntel] Analyzing social sentiment for ${protocolAddress}`,
  );

  // MVP: Return 0.0 (neutral sentiment)
  // Production: Integrate with Twitter API, sentiment analysis service, or LunarCrush
  // Example API call structure (commented out):
  /*
  const http = new HTTPClient();
  const apiKey = nodeRuntime.getSecret({ id: "TWITTER_API_KEY" }).result().value;
  
  const response = http.sendRequest(nodeRuntime, {
    url: `https://api.twitter.com/2/tweets/search/recent?query=${protocolAddress}`,
    method: "GET",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
    },
  }).result();
  
  if (ok(response)) {
    const data = json(response) as any;
    // Perform sentiment analysis on tweets
    // Return aggregated sentiment score
  }
  */

  return 0.0;
}

// ---------------------------------------------------------------------------
// Unified Threat Intelligence Fetcher
// ---------------------------------------------------------------------------

/**
 * Fetches all threat intelligence data for a protocol.
 * Aggregates data from multiple sources: CVE databases, exploit patterns,
 * dark web intelligence, and social sentiment.
 * 
 * @param nodeRuntime - CRE NodeRuntime for HTTP access
 * @param protocolAddress - Target protocol contract address
 * @returns Complete ThreatIntelligence object
 */
export function fetchThreatIntelligence(
  nodeRuntime: NodeRuntime<any>,
  protocolAddress: string,
): ThreatIntelligence {
  nodeRuntime.log(
    `[ThreatIntel] Fetching comprehensive threat intelligence for ${protocolAddress}`,
  );

  // Fetch all threat intel data in parallel (within CRE's synchronous model)
  const activeCVEs = fetchActiveCVEs(nodeRuntime, protocolAddress);
  const exploitPatterns = fetchExploitPatterns(nodeRuntime, protocolAddress);
  const darkWebMentions = fetchDarkWebMentions(nodeRuntime, protocolAddress);
  const socialSentiment = fetchSocialSentiment(nodeRuntime, protocolAddress);

  nodeRuntime.log(
    `[ThreatIntel] Summary: CVEs=${activeCVEs.length}, patterns=${exploitPatterns.length}, darkWeb=${darkWebMentions}, sentiment=${socialSentiment.toFixed(2)}`,
  );

  return {
    activeCVEs,
    exploitPatterns,
    darkWebMentions,
    socialSentiment,
  };
}
