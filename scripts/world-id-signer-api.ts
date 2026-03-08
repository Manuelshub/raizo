import { signRequest } from "@worldcoin/idkit-server";
import { config } from "dotenv";
import http from "http";
import fs from "fs";
import path from "path";

config();

const SIGNER_KEY = process.env.WORLDID_SIGNER_KEY;

const server = http.createServer((req, res) => {
    // Enable CORS for frontend requests on port 3000
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    if (req.url === '/sign') {
        console.log("Signing request...");
        try {
            if (!SIGNER_KEY) throw new Error("WORLDID_SIGNER_KEY is missing from .env");
            // Generates the 5-minute TTL signed rp_context payload natively
            const rpSignature = signRequest("raizo-governance-propose", SIGNER_KEY);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(rpSignature));
        } catch (e: any) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: e.message }));
        }
    } else if (req.url === '/world-id-verify.html' || req.url === '/') {
        // 2. Static Frontend Route (same-origin, bypasses ad-blockers)
        const filePath = path.join(__dirname, '../public/world-id-verify.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end("Frontend file not found.");
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else {
        res.writeHead(404);
        res.end();
    }
});

server.listen(3001, () => {
    console.log("Unified IDKit Relay & Frontend running on http://localhost:3001");
    console.log("--> Open http://localhost:3001/world-id-verify.html to request a pristine Simulator Proof!");
});
