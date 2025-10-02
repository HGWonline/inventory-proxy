import express from "express";
import fetch from "node-fetch";

const app = express();

// Render가 지정하는 포트를 사용해야 함
const PORT = process.env.PORT || 3000;

// 환경변수 (Render 대시보드에서 설정)
const SHOP = process.env.SHOPIFY_SHOP;               // 예: "your-shop.myshopify.com"
const ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN; // Admin API Access Token
const API_VER = process.env.SHOPIFY_API_VER || "2024-10";

// (선택) 노출할 Location GID 화이트리스트를 콤마로 나열
// 예: "gid://shopify/Location/111,gid://shopify/Location/222"
const ALLOWED_LOCATION_IDS = (process.env.ALLOWED_LOCATION_IDS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);
const allowSet = new Set(ALLOWED_LOCATION_IDS);

// 간단 메모리 캐시(서버가 유지되는 동안만, TTL=60초) - 선택
const cache = new Map();
const TTL_MS = 60 * 1000;

async function adminGraphQL(query, variables = {}) {
  const url = `https://${SHOP}/admin/api/${API_VER}/graphql.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": ADMIN_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  });
  const json = await res.json();
  if (!res.ok || json.errors) {
    throw new Error(`Admin GraphQL error: ${res.status} ${JSON.stringify(json.errors || json)}`);
  }
  return json.data;
}

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

// App Proxy가 때리는 엔드포인트 (Render URL과 연결됨)
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
    if (c && (now - c.t) < TTL_MS) return res.status(200).json(c.v);

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
    let levels = (d2?.inventoryItem?.inventoryLevels?.edges || []).map(e => ({
      locationId: e.node.location.id,
      location: e.node.location.name,
      available: e.node.available ?? 0
    }));

    if (allowSet.size) levels = levels.filter(l => allowSet.has(l.locationId));
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
