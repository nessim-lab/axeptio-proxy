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
        // Extract only what we need (keep payload small)
        const cookies = (data.data?.cookies || []).map(c => ({
          name: c.name,
          domain: c.domain,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite,
        }));

        const requests = data.data?.requests || [];
        const thirdPartyDomains = [...new Set(
          requests
            .map(r => { try { return new URL(r.request?.request?.url).hostname; } catch { return null; } })
            .filter(Boolean)
        )];

        const allUrls = requests.map(r => r.request?.request?.url || "");
        const consentModeV2 = allUrls.some(u => u.includes("gcs=") || u.includes("gcd=") || u.includes("G100"));

        return res.status(200).json({
          uuid,
          screenshot: data.task?.screenshotURL || null,
          cookies,
          third_party_domains: thirdPartyDomains,
          requests_count: requests.length,
          consent_mode_v2_signal: consentModeV2,
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
