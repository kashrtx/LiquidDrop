use crate::app::App;
use crate::assets;
use crate::util::html_escape;

const HOST_SECTION: &str = r#"<div class="app-stack app-host-shell"><div class="host-panel glass fade-in app-host" style="animation-delay:.08s">
  <div class="host-panel-head">
    <div>
      <div class="host-eyebrow">Host Controls</div>
      <h2>This computer is running LiquidDrop</h2>
      <p id="hostStatusNote">Stop sharing when you're finished.</p>
    </div>
    <div class="host-status">Host Only</div>
  </div>
  <div class="host-network" id="hostNetwork" hidden>
    <label for="hostNetworkSelect">Share on network</label>
    <select id="hostNetworkSelect"></select>
    <div class="host-network-hint" id="hostNetworkHint"></div>
  </div>
  <button class="stop-btn" id="stopServerBtn">⏹ Stop LiquidDrop</button>
</div></div>"#;

/// Scripts may only come from LiquidDrop itself, the page's own nonce'd
/// inline script, or the pdf.js CDNs used as a fallback by the preview add-on.
/// Inline event handlers (`onclick=` etc.) and injected inline scripts are blocked.
pub fn csp(nonce: &str) -> String {
    format!(
        "script-src 'self' 'nonce-{}' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; \
         worker-src 'self' blob: https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        nonce
    )
}

pub fn index(app: &App, is_host: bool, nonce: &str) -> String {
    let (lock, label, detail) = if app.secure {
        let fp: String = app.fingerprint.chars().take(23).collect();
        ("🔒", "TLS Encrypted · HTTPS", format!("SHA-256: {}…", fp))
    } else {
        (
            "🌐",
            "Local Network · HTTP",
            "Secret token protected · WiFi encrypted (WPA)".to_string(),
        )
    };
    assets::get_str("ui/index.html")
        .replace("{{APP_CSS}}", assets::get_str("ui/app.css"))
        .replace("{{BODY_CLASS}}", if is_host { "host-view" } else { "" })
        .replace("{{LOCK_ICON}}", lock)
        .replace("{{SEC_LABEL}}", label)
        .replace("{{SEC_DETAIL}}", &html_escape(&detail))
        .replace("{{TOKEN}}", &html_escape(&app.token))
        .replace("{{BASE_URL}}", &html_escape(&app.base_url()))
        .replace("{{PIN}}", &html_escape(&app.pin))
        .replace("{{PIN_URL}}", &html_escape(&app.pin_url()))
        .replace("{{HOST_SECTION}}", if is_host { HOST_SECTION } else { "" })
        .replace("{{NONCE}}", nonce)
        // Inserted last so nothing inside the script is ever treated as a placeholder.
        .replace("{{APP_JS}}", assets::get_str("ui/app.js"))
}

pub fn pin(error: bool, locked: bool, nonce: &str) -> String {
    let message = if locked {
        r#"<div style="color:#f472b6;font-size:13px;margin-top:12px;font-weight:600">Too many attempts. Try again in 60 seconds.</div>"#
    } else if error {
        r#"<div style="color:#f472b6;font-size:13px;margin-top:12px;font-weight:600">Wrong PIN. Try again.</div>"#
    } else {
        ""
    };
    assets::get_str("ui/pin.html")
        .replace("{{ERR_CLASS}}", if error { " error" } else { "" })
        .replace("{{MESSAGE}}", message)
        .replace("{{NONCE}}", nonce)
}
