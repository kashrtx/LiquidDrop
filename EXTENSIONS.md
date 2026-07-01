# LiquidDrop Extensions

LiquidDrop extensions are small client-side add-ons. They can react to the file list, read extension settings, upload generated shared files, and store extension-owned assets such as background images.

Extension management is host-only. Connected devices can use enabled extensions, but installing, uninstalling, enabling, disabling, configuring, and uploading extension assets must be done from the computer running LiquidDrop.

## Built-in extensions

LiquidDrop ships with a small bundled set in `assets/extensions/`:

- `liquiddrop.background`: custom image or GIF backgrounds with blur, readability controls, reset defaults, and live sync across open devices.
- `liquiddrop.preview`: an in-page preview player for images, videos, audio, PDFs, DOCX, and text-like files with zoom controls, iPhone-friendly PDF page scrolling, and a calmer audio visualizer.
- `liquiddrop.status-strip`: configurable modern header widgets for active devices, local transfer speed, and no-signup weather via Open-Meteo.

## Folder layout

User extensions live in:

```text
~/LiquidDrop/extensions/<extension-id>/
  manifest.json
  client.js
  style.css       # optional
```

A folder extension appears after you refresh the Extensions tab or reload LiquidDrop.

## Minimal extension

Create `~/LiquidDrop/extensions/example.hello/manifest.json`:

```json
{
  "id": "example.hello",
  "name": "Hello Action",
  "version": "1.0.0",
  "description": "Shows a toast when LiquidDrop loads.",
  "author": "You",
  "category": "Example",
  "default_enabled": false,
  "capabilities": ["Toast"],
  "client": {"script": "client.js"},
  "settings_schema": [
    {"key": "message", "label": "Message", "type": "string", "default": "Hello from my extension"}
  ]
}
```

Create `~/LiquidDrop/extensions/example.hello/client.js`:

```js
(function () {
  const id = 'example.hello';
  const api = window.LiquidDropExtensions;
  if (!api) return;

  api.getSettings(id).then((settings) => {
    api.toast(settings.message || 'Hello from my extension', 'success');
  });
})();
```

Refresh the Extensions tab, turn the extension on, then reload the page so its script is loaded.

## Installable JSON extension

The Extensions tab can install a single JSON file. Use `client.inline_js` when you want a one-file extension:

```json
{
  "id": "example.onefile",
  "name": "One File Example",
  "version": "1.0.0",
  "description": "Installed directly from a JSON file.",
  "client": {
    "inline_js": "(function(){const api=window.LiquidDropExtensions;if(api)api.toast('One-file extension loaded','success');})();"
  }
}
```

Uploaded extensions are installed disabled. Turn them on from the Extensions tab, then LiquidDrop reloads so the script can be loaded cleanly.

## Manifest reference

Required fields:

- `id`: lowercase letters, numbers, dots, dashes, or underscores. Maximum 64 characters.
- `name`: display name.
- `version`: display version.
- `client.script`: relative path to the JavaScript file.

Common optional fields:

- `description`, `author`, `category`
- `default_enabled`: `true` or `false`
- `capabilities`: short labels shown on the extension card
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

## Client API

Enabled extension scripts can use `window.LiquidDropExtensions`:

```js
api.getSettings(id)
api.saveSettings(id, settings)
api.uploadAsset(id, file)
api.uploadFile(file, displayName)
api.listFiles()
api.getSelectedFiles()
api.toast(message, type)
api.escapeHtml(value)
api.formatSize(bytes)
api.apiBase
```

Notes:

- `saveSettings` and `uploadAsset` are host-only.
- `uploadFile` uploads into the normal shared files list.
- `getSelectedFiles` returns filenames selected in the Shared Files panel.
- `apiBase` is the token-prefixed base path, such as `/abc123`.

## Testing checklist

1. Start LiquidDrop and open the host view.
2. Open the Extensions tab and confirm your extension appears.
3. Turn it on. LiquidDrop reloads so scripts are loaded from a clean page state.
4. Open DevTools Console and check for JavaScript errors.
5. Test mobile and desktop widths.
6. Toggle the extension off and confirm a reload removes its behavior.
7. If your extension uploads files or assets, restart LiquidDrop and verify they still work.

## Security rules

Extensions run JavaScript inside LiquidDrop pages. Only install extensions you trust.

Do not store passwords, API keys, access tokens, or private credentials in extension settings. Settings can be read by enabled extension scripts in connected browsers.

Keep network access explicit. LiquidDrop is designed for local sharing; extensions should not silently send file data to remote services.
