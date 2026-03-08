import http from 'http';

// This mock server perfectly simulates the World ID v4 Verify API success response.
// It allows the CLI demo to execute flawlessly and show the "Verified!" state without
// needing real proof generation or API keys from the Worldcoin Developer Portal.

const server = http.createServer((req, res) => {
    // Only accept POST requests to the verify endpoint
    if (req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            console.log(`\n[Mock API] Received POST request to: ${req.url}`);
            try {
                const parsed = JSON.parse(body);
                console.log(`[Mock API] Payload:`, parsed);
            } catch (e) {
                console.log(`[Mock API] Could not parse body`);
            }

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                action: "raizo-governance-propose",
                created_at: Math.floor(Date.now() / 1000),
                results: [{
                    success: true,
                    identifier: "app_demo_raizo_sentinel",
                    nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222"
                }]
            }));
            
            console.log(`[Mock API] Returned 200 OK 'Verified' response.`);
        });
    } else {
        res.writeHead(404);
        res.end();
    }
});

const PORT = 3002;
server.listen(PORT, () => {
    console.log(`Mock World ID Verify API running on http://localhost:${PORT}`);
    console.log(`Update config.staging.json apiUrl to point here to achieve the 'Verified!' state in the simulation.`);
});
