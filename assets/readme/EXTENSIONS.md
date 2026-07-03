# LiquidDrop Add-ons

LiquidDrop add-ons are small client-side extensions. They can react to the file list, read host-managed settings, publish host-approved shared state to connected devices, upload generated shared files, and store add-on-owned assets such as background images.

Add-on management is host-only. Connected phones and tablets can use enabled add-ons and read synced state, but installing, creating, uninstalling, enabling, disabling, configuring, and uploading add-on assets must be done from the computer running LiquidDrop.

## Built-in add-ons

LiquidDrop ships with a bundled set in `assets/extensions/`:

- `liquiddrop.background`: custom image or GIF backgrounds with blur, readability controls, reset defaults, and live sync across open devices.
- `liquiddrop.preview`: an in-page preview player for images, videos, audio, PDFs, DOCX, and text-like files with zoom controls, iPhone-friendly PDF page scrolling, and calmer audio visualization.
- `liquiddrop.status-strip`: configurable header widgets for active devices, local transfer speed, and host-synced weather via Open-Meteo.

## Easiest path

1. Start LiquidDrop on the host computer.
2. Open the **Extensions** tab.
3. Click **Create Add-on**.
4. Enter a name, ID, creator, and description.
5. Click **Create Starter**.
6. Click **Open Folder** to edit the generated `client.js` and `manifest.json`.
7. Refresh the Extensions tab, turn the add-on on, then reload the page.

The generated starter is intentionally small. It includes settings, a visible UI change, error reporting, and cross-device shared state so new creators can copy working patterns instead of starting from nothing.

## Folder layout

User add-ons live in:

```text
~/LiquidDrop/extensions/<extension-id>/
  manifest.json
  client.js
  style.css       # optional
```

A folder add-on appears after you refresh the Extensions tab or reload LiquidDrop.

## Minimal add-on

Create `~/LiquidDrop/extensions/example.hello/manifest.json`:

```json
{
  "id": "example.hello",
  "name": "Hello Action",
  "version": "1.0.0",
  "description": "Shows a toast when LiquidDrop loads.",
  "author": "You",
  "created_at": "2026-07-03T00:00:00Z",
  "updated_at": "2026-07-03T00:00:00Z",
  "license": "Creator retains rights",
  "category": "Example",
  "default_enabled": false,
  "capabilities": ["Toast"],
  "client": {"script": "client.js"},
  "settings_schema": [
    {"key": "message", "label": "Message", "type": "string", "default": "Hello from my add-on"}
  ]
}
```

Create `~/LiquidDrop/extensions/example.hello/client.js`:

```js
(function () {
  const id = 'example.hello';
  const api = window.LiquidDropExtensions;
  if (!api) return;

  async function start() {
    const settings = await api.getSettings(id);
    api.toast(settings.message || 'Hello from my add-on', 'success');
  }

  start().catch((error) => api.reportError(id, error));
})();
```

## Manifest reference

Required fields:

- `id`: lowercase letters, numbers, dots, dashes, or underscores. Maximum 64 characters.
- `name`: display name.
- `version`: display version.
- `client.script`: relative path to the JavaScript file.

Recommended ownership fields:

- `author`: creator name shown in the Extensions tab.
- `created_at`: ISO date/time when the add-on was created.
- `updated_at`: ISO date/time for the last update.
- `license`: rights statement. Use `Creator retains rights` when the creator keeps ownership.

Common optional fields:

- `description`, `category`
- `default_enabled`: `true` or `false`
- `capabilities`: short labels shown on the add-on card
- `client.style`: relative path to an optional CSS file
- `settings_schema`: configurable fields rendered by LiquidDrop
- `settings_defaults`: extra default values not shown in the generic settings form

Supported setting field types:

- `string`
- `text`
- `number` with optional `min`, `max`, `step`
- `boolean`
- `select` with `options`
- `color`
- `asset` with optional `accept` and `name_key`

## Cross-device state

Use shared state when the host should calculate or choose something once, then all connected devices should see the same result. Weather sync uses this path: the host browser reads location and weather, then iPhones read the shared weather result.

```js
const shared = await api.getSharedState(id);

if (api.canManage()) {
  await api.setSharedState(id, {
    message: 'Synced from the host',
    updatedAt: new Date().toISOString()
  });
}
```

Rules:

- `getSharedState(id)` works on every connected device.
- `setSharedState(id, state)` is host-only.
- Shared state must be a JSON object and is size-limited.
- Do not store passwords, API keys, or private credentials in settings or shared state.

## Client API

Enabled add-on scripts can use `window.LiquidDropExtensions`:

```js
api.canManage()
api.getSettings(id)
api.saveSettings(id, settings)
api.getSharedState(id)
api.setSharedState(id, state)
api.uploadAsset(id, file)
api.uploadFile(file, displayName)
api.listFiles()
api.getSelectedFiles()
api.reportError(id, error)
api.toast(message, type)
api.escapeHtml(value)
api.formatSize(bytes)
api.apiBase
```

Notes:

- `saveSettings`, `setSharedState`, and `uploadAsset` are host-only.
- `uploadFile` uploads into the normal shared files list.
- `getSelectedFiles` returns filenames selected in the Shared Files panel.
- `reportError` marks the add-on card as errored with a useful message.
- `apiBase` is the token-prefixed base path, such as `/abc123`.

## Safety model

LiquidDrop validates manifest shape, blocks unsafe relative paths, prevents add-on file access outside the add-on folder, and skips invalid manifests before running any add-on JavaScript. The Extensions tab shows status, safety, creator, date, and diagnostic messages.

Add-ons still run JavaScript inside LiquidDrop pages, so only enable code you trust. A broken add-on should show an error card instead of taking down LiquidDrop, but JavaScript cannot be treated like a fully sandboxed package.

## Testing checklist

1. Start LiquidDrop and open the host view.
2. Open the Extensions tab and confirm your add-on appears.
3. Check the card status. Fix manifest or script errors before enabling widely.
4. Turn it on. LiquidDrop reloads so scripts are loaded from a clean page state.
5. Open DevTools Console and check for JavaScript errors.
6. Test mobile and desktop widths.
7. Connect another device and verify settings/shared state sync.
8. Toggle the add-on off and confirm a reload removes its behavior.
9. If your add-on uploads files or assets, restart LiquidDrop and verify they still work.

## Installable JSON add-on

The Extensions tab can install a single JSON file. Use `client.inline_js` when you want a one-file add-on:

```json
{
  "id": "example.onefile",
  "name": "One File Example",
  "version": "1.0.0",
  "description": "Installed directly from a JSON file.",
  "author": "You",
  "license": "Creator retains rights",
  "client": {
    "inline_js": "(function(){const api=window.LiquidDropExtensions;if(api)api.toast('One-file add-on loaded','success');})();"
  }
}
```

Uploaded add-ons are installed disabled. Turn them on from the Extensions tab, then LiquidDrop reloads so the script can be loaded cleanly.
