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

        // ── Consent Mode — détection via paramètre gcs= dans les URLs réseau ──
        // Le paramètre gcs= est envoyé en GET vers google-analytics.com
        // Format gcs : G1XX (4 chars) = v1 | G1XXXX (6 chars) = v2
        // car v2 ajoute ad_user_data + ad_personalization (2 chars supplémentaires)
        const gcsValue = allUrls.map(u => u.match(/[?&]gcs=([^&\s]+)/)?.[1]).find(Boolean) || null;
        const gcdValue = allUrls.map(u => u.match(/[?&]gcd=([^&\s]+)/)?.[1]).find(Boolean) || null;

        // ── Consent Mode — détection en 2 niveaux ──────────────────────────

        // Niveau 1 : Advanced CM — paramètre gcs= dans les URLs GA4
        // gcs v1 = 4 chars (ex: G100), gcs v2 = 6 chars (ex: G10000)
        const hasCM = !!(gcsValue || gcdValue);
        const consentModeV2Advanced = hasCM && gcsValue ? gcsValue.length >= 6 : false;
        const consentModeV1Advanced = hasCM && !consentModeV2Advanced;

        // Niveau 2 : Basic CM — lire le container GTM pour chercher
        // ad_user_data et ad_personalization dans gtag('consent','default',{...})
        let consentModeV2Basic = false;
        let consentModeV1Basic = false;
        let gtmContainerCode = null;
        try {
          const gtmUrl = allUrls.find(u => u.includes("googletagmanager.com/gtm.js"));
          if (gtmUrl) {
            const gtmRes = await fetch(gtmUrl, { signal: AbortSignal.timeout(5000) });
            if (gtmRes.ok) {
              gtmContainerCode = await gtmRes.text();
              const hasAdUserData        = gtmContainerCode.includes("ad_user_data");
              const hasAdPersonalization = gtmContainerCode.includes("ad_personalization");
              const hasConsentDefault    = gtmContainerCode.includes("consent") && gtmContainerCode.includes("default");
              if (hasConsentDefault && hasAdUserData && hasAdPersonalization) {
                consentModeV2Basic = true;
              } else if (hasConsentDefault) {
                consentModeV1Basic = true;
              }
            }
          }
        } catch(_) { /* GTM fetch optionnel */ }

        const consentModeV2 = consentModeV2Advanced || consentModeV2Basic;
        const consentModeV1 = !consentModeV2 && (consentModeV1Advanced || consentModeV1Basic);
        // ───────────────────────────────────────────────────────────────────
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
