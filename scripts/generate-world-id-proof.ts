import { signRequest } from "@worldcoin/idkit-server";
import { IDKit, orbLegacy } from "@worldcoin/idkit-core";
import { config } from "dotenv";
config();

// Script to generate a staging simulator request securely using IDKit and our signer key.
const APP_ID = "app_f50f0c294fd5aef73d093bc24c44c01c";
const RP_ID = "rp_aa1cd1f82b8d58fa";
const ACTION = "raizo-governance-propose";
const SIGNER_KEY = process.env.WORLDID_SIGNER_KEY;

async function generateSimUrl() {
    console.log("Initializing IDKit backend request...");
    if (!SIGNER_KEY) throw new Error("WORLDID_SIGNER_KEY is missing from .env");

    try {
        // Generate the backend signature
        const rpSignature = signRequest(ACTION, SIGNER_KEY);

        // Initiate the IDKit 4.0 Request
        const request = await IDKit.request({
            app_id: APP_ID,
            action: ACTION,
            rp_context: {
                rp_id: RP_ID,
                nonce: rpSignature.nonce,
                created_at: rpSignature.createdAt,
                expires_at: rpSignature.expiresAt,
                signature: rpSignature.sig,
            },
            allow_legacy_proofs: true,
            environment: "staging", // Simulator environment
        }).preset(orbLegacy({ signal: "" }));

        const connectUrl = request.connectorURI;
        console.log("\n--- STAGING SIMULATOR URL ---");
        console.log("1. Open: https://simulator.worldcoin.org/");
        console.log("2. Paste this URI to connect:");
        console.log(connectUrl);
        console.log("\nWaiting for you to approve in the simulator...");

        // This polls the World ID infrastructure until you approve on the simulator
        const response = await request.pollUntilCompletion();
        
        console.log("\n✅ Proof successfully generated!");
        console.log(JSON.stringify(response, null, 2));

    } catch (err) {
        console.error("IDKit flow failed:", err);
    }
}

generateSimUrl().catch(console.error);
