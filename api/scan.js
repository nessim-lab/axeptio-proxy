module.exports = async function handler(req, res) {
  // CORS — autorise l'artifact Claude
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing url param" });

  const URLSCAN_KEY = process.env.URLSCAN_API_KEY;

  try {
    // 1. Submit scan
    const submit = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": URLSCAN_KEY,
      },
      body: JSON.stringify({ url, visibility: "private" }),
    });
    if (!submit.ok) {
      const err = await submit.json();
      return res.status(500).json({ error: `URLScan submit failed: ${err.message}` });
    }
    const { uuid } = await submit.json();

    // 2. Poll for result (max 60s)
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const result = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { "API-Key": URLSCAN_KEY },
      });
      if (result.ok) {
        const data = await result.json();

        // Cookies
        const cookies = (data.data?.cookies || []).map(c => ({
          name: c.name,
          domain: c.domain,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite,
        }));

        // Requêtes réseau
        const requests = data.data?.requests || [];
        const allUrls = requests.map(r => r.request?.request?.url || "");

        // Domaines tiers
        const thirdPartyDomains = [...new Set(
          allUrls
            .map(u => { try { return new URL(u).hostname; } catch { return null; } })
            .filter(Boolean)
        )];

        // ── Consent Mode — approche InfoTrust ──────────────────────────────
        // CM v2 : paramètres ad_user_data ou ad_personalization dans les URLs
        const hasAdUserData        = allUrls.some(u => u.includes("ad_user_data"));
        const hasAdPersonalization = allUrls.some(u => u.includes("ad_personalization"));
        const consentModeV2        = hasAdUserData || hasAdPersonalization;

        // CM v1 : paramètres gcs= ou gcd= présents sans signaux v2
        const hasGCS        = allUrls.some(u => /[?&]gcs=/.test(u));
        const hasGCD        = allUrls.some(u => /[?&]gcd=/.test(u));
        const consentModeV1 = !consentModeV2 && (hasGCS || hasGCD);

        // Valeurs brutes pour debug
        const gcdValue = allUrls.map(u => u.match(/[?&]gcd=([^&]+)/)?.[1]).find(Boolean) || null;
        const gcsValue = allUrls.map(u => u.match(/[?&]gcs=([^&]+)/)?.[1]).find(Boolean) || null;
        // ───────────────────────────────────────────────────────────────────

        return res.status(200).json({
          uuid,
          screenshot: data.task?.screenshotURL || null,
          cookies,
          third_party_domains: thirdPartyDomains,
          requests_count: requests.length,
          consent_mode_v2_signal: consentModeV2,
          consent_mode_v1_signal: consentModeV1,
          gcd_value: gcdValue,
          gcs_value: gcsValue,
          page: {
            url: data.page?.url,
            domain: data.page?.domain,
            country: data.page?.country,
          },
        });
      }
    }
    return res.status(504).json({ error: "URLScan timeout — réessayez" });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
