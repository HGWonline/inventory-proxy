import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

// Render가 지정하는 포트를 사용해야 함
const PORT = process.env.PORT || 3000;

// ====== 공통 환경변수 ======
const SHOP = process.env.SHOPIFY_SHOP;                 // 예: "your-shop.myshopify.com"
const API_VER = process.env.SHOPIFY_API_VER || "2024-10";

// ----- OAuth용 (Partner 앱 자격증명) -----
const API_KEY = process.env.SHOPIFY_API_KEY;           // Partner 앱 API key
const API_SECRET = process.env.SHOPIFY_API_SECRET;     // Partner 앱 API secret
const APP_URL = process.env.APP_URL;                   // 예: "https://inventory-proxy-xxxx.onrender.com"
const REDIRECT_URI = `${APP_URL}/auth/callback`;
const OAUTH_SCOPES = "read_products,read_inventory,read_locations";

// ----- Admin 호출용 토큰 -----
// OAuth 완료 후 Render 환경변수에 저장해 사용
let ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;

// (선택) 노출할 Location GID 화이트리스트를 콤마로 나열
// 예: "gid://shopify/Location/111,gid://shopify/Location/222"
const ALLOWED_LOCATION_IDS = (process.env.ALLOWED_LOCATION_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const allowSet = new Set(ALLOWED_LOCATION_IDS);

// 간단 메모리 캐시(서버가 유지되는 동안만, TTL=60초) - 선택
const cache = new Map();
const TTL_MS = 60 * 1000;

// ====== Admin GraphQL 공통 함수 ======
async function adminGraphQL(query, variables = {}) {
  if (!SHOP) throw new Error("SHOPIFY_SHOP not configured");
  if (!ADMIN_TOKEN) throw new Error("SHOPIFY_ADMIN_TOKEN not configured (finish OAuth and set it)");
  const url = `https://${SHOP}/admin/api/${API_VER}/graphql.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": ADMIN_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (!res.ok || json.errors) {
    throw new Error(`Admin GraphQL error: ${res.status} ${JSON.stringify(json.errors || json)}`);
  }
  return json.data;
}

// ====== GraphQL 쿼리 ======
const QUERY_VARIANT_TO_ITEM = `
  query VariantToItem($id: ID!) {
    productVariant(id: $id) { id inventoryItem { id } }
  }
`;

const QUERY_ITEM_LEVELS = `
  query ItemLevels($id: ID!, $first: Int = 50) {
    inventoryItem(id: $id) {
      id
      inventoryLevels(first: $first) {
        edges { node { available location { id name } } }
      }
    }
  }
`;

// ====== OAuth: 설치 시작 (/auth/install?shop=...) ======
const stateStore = new Map(); // 데모용. 운영은 KV/DB 권장.

app.get("/auth/install", (req, res) => {
  try {
    const { shop } = req.query;
    if (!shop) return res.status(400).send("Missing shop");
    if (!API_KEY || !API_SECRET || !APP_URL) return res.status(500).send("OAuth env not configured");

    const state = crypto.randomBytes(16).toString("hex");
    stateStore.set(state, Date.now());

    const url = new URL(`https://${shop}/admin/oauth/authorize`);
    url.searchParams.set("client_id", API_KEY);
    url.searchParams.set("scope", OAUTH_SCOPES);
    url.searchParams.set("redirect_uri", REDIRECT_URI);
    url.searchParams.set("state", state);

    return res.redirect(url.toString());
  } catch (e) {
    console.error(e);
    return res.status(500).send("Auth install error");
  }
});

// ====== OAuth: 콜백 (/auth/callback) ======
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, hmac, code, state, timestamp } = req.query;
    if (!shop || !hmac || !code || !state) return res.status(400).send("Missing params");

    // state 검증
    if (!stateStore.has(state)) return res.status(400).send("Invalid state");

    // HMAC 검증
    const params = { shop, code, state, timestamp };
    const message = Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join("&");
    const generated = crypto.createHmac("sha256", API_SECRET).update(message).digest("hex");
    if (generated !== hmac) return res.status(400).send("Invalid HMAC");

    // 코드 → access_token 교환
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: API_KEY,
        client_secret: API_SECRET,
        code,
      }),
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok || !tokenJson.access_token) {
      console.error("Token exchange failed:", tokenJson);
      return res.status(500).send("Token exchange failed");
    }

    const accessToken = tokenJson.access_token;

    // ⚠️ 운영에서는 안전한 저장소(DB/환경변수 관리)로 보관하고 로그를 남기지 마세요.
    console.log("✅ Admin API Access Token acquired.");
    ADMIN_TOKEN = accessToken; // 프로세스 메모리에 반영 (재배포 전 임시 사용)

    // 안내문 (이후 Render 대시보드에 SHOPIFY_ADMIN_TOKEN으로 저장하고 재배포 권장)
    return res.send(
      "App installed! Access token acquired.<br/>" +
        "Copy this token from server logs and set it to SHOPIFY_ADMIN_TOKEN env, then redeploy.<br/>" +
        "After that, /proxy will use the stored token."
    );
  } catch (e) {
    console.error(e);
    return res.status(500).send("Auth callback error");
  }
});

// ====== App Proxy 엔드포인트 (/proxy) ======
app.get("/proxy", async (req, res) => {
  try {
    // 보안: App Proxy에서 전달되는 스토어 도메인 확인(간단 화이트리스트)
    const shopDomain = req.headers["x-shopify-shop-domain"];
    if (!shopDomain || shopDomain !== SHOP) {
      return res.status(403).json({ error: "forbidden" });
    }

    const variantIdRaw = req.query.variant_id;
    if (!variantIdRaw) return res.status(400).json({ error: "variant_id required" });

    const cacheKey = `levels:${variantIdRaw}`;
    const now = Date.now();
    const c = cache.get(cacheKey);
    if (c && now - c.t < TTL_MS) return res.status(200).json(c.v);

    // 숫자형이면 GID로 변환
    const variantGID = variantIdRaw.startsWith("gid://")
      ? variantIdRaw
      : `gid://shopify/ProductVariant/${variantIdRaw}`;

    // 1) Variant -> InventoryItem
    const d1 = await adminGraphQL(QUERY_VARIANT_TO_ITEM, { id: variantGID });
    const itemId = d1?.productVariant?.inventoryItem?.id;
    if (!itemId) return res.status(200).json({ levels: [] });

    // 2) InventoryItem -> Levels
    const d2 = await adminGraphQL(QUERY_ITEM_LEVELS, { id: itemId, first: 50 });
    let levels =
      d2?.inventoryItem?.inventoryLevels?.edges?.map((e) => ({
        locationId: e.node.location.id,
        location: e.node.location.name,
        available: e.node.available ?? 0,
      })) || [];

    if (allowSet.size) levels = levels.filter((l) => allowSet.has(l.locationId));
    levels.sort((a, b) => a.location.localeCompare(b.location));

    const payload = { levels };
    cache.set(cacheKey, { t: now, v: payload });
    return res.status(200).json(payload);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "inventory lookup failed" });
  }
});

// 헬스체크(선택)
app.get("/", (req, res) => res.send("OK"));

app.listen(PORT, () => {
  console.log(`inventory proxy running on :${PORT}`);
});
