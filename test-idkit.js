import { IDKit, orbLegacy } from "@worldcoin/idkit-core";
const req = await IDKit.request({
  app_id: "app_f50f0c294fd5aef73d093bc24c44c01c",
  action: "vote",
  environment: "staging",
  rp_context: { rp_id: "vote", nonce: "0x1", created_at: 1, expires_at: 2, signature: "0x3" }
}).preset(orbLegacy({ signal: "" }));
console.log(req.connectorURI);
