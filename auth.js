// auth.js
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const router = express.Router();

const API_KEY = process.env.SHOPIFY_API_KEY;       // Partner앱 API key
const API_SECRET = process.env.SHOPIFY_API_SECRET; // Partner앱 API secret
const SCOPES = "read_products,read_inventory,read_locations";
const APP_URL = process.env.APP_URL;               // 예: https://inventory-proxy-xxxx.onrender.com
const REDIRECT_URI = `${APP_URL}/auth/callback`;

// 매우 단순한 state 저장소(데모용). 실서비스는 DB/kv 사용 권장.
const stateStore = new Map();

// 1) 설치 시작: /auth/install?shop=스토어도메인
router.get("/auth/install", (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send("Missing shop");

  const state = crypto.randomBytes(16).toString("hex");
  stateStore.set(state, Date.now());

  const url = new URL(`https://${shop}/admin/oauth/authorize`);
  url.searchParams.set("client_id", API_KEY);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("state", state);

  return res.redirect(url.toString());
});

// 2) 콜백: Shopify가 code/hmac/state/…를 붙여 호출
router.get("/auth/callback", async (req, res) => {
  try {
    const { shop, hmac, code, state, timestamp } = req.query;
    if (!shop || !hmac || !code || !state) return res.status(400).send("Missing params");

    // state 검증
    if (!stateStore.has(state)) return res.status(400).send("Invalid state");

    // HMAC 검증
    const params = { shop, code, state, timestamp };
    const message = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("&");
    const generated = crypto.createHmac("sha256", API_SECRET).update(message).digest("hex");
    if (generated !== hmac) return res.status(400).send("Invalid HMAC");

    // 코드 → 토큰 교환
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: API_KEY, client_secret: API_SECRET, code })
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok || !tokenJson.access_token) {
      console.error("Token exchange failed:", tokenJson);
      return res.status(500).send("Token exchange failed");
    }

    const accessToken = tokenJson.access_token;

    // 👉 여기서 accessToken을 안전하게 저장하세요(환경변수/DB).
    // 데모로는 로그에 한 번 출력 (운영에서는 금지)
    console.log("✅ Admin API Access Token:", accessToken);

    return res.send("App installed! Access token acquired. Check your server logs and store it securely.");
  } catch (e) {
    console.error(e);
    return res.status(500).send("Auth callback error");
  }
});

export default router;
