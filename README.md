# GuardExt

A Chrome extension that scans your installed browser extensions and flags potential security risks.

## Features

- **Permission analysis** — Detects dangerous and sensitive permissions (`webRequestBlocking`, `debugger`, `cookies`, `clipboardRead`, etc.) and broad host access patterns (`<all_urls>`, `*://*/*`).
- **Install type checks** — Flags sideloaded and developer-mode extensions that weren't installed from the Chrome Web Store.
- **Malicious ID blocklist** — Cross-references each extension against a bundled list of known malicious extension IDs. Matches are tagged with a `BLOCKLISTED` badge and the specific reason.
- **Risk scoring** — Each extension receives a composite score and is categorized as Safe, Warning, or Danger.
- **Auto-updating blocklist** — A GitHub Actions workflow publishes `malicious_ids.json` to GitHub Pages on every push to `main`, so the extension can fetch the latest blocklist at scan time with a local fallback.

## Project Structure

```
guardext/
├── manifest.json
├── background/
│   └── background.js             # Service worker: risk analysis & blocklist loading
├── popup/
│   ├── popup.html                # Popup UI
│   ├── popup.js                  # Scan trigger, results rendering
│   └── popup.css                 # Dark-themed styles
├── data/
│   └── malicious_ids.json        # Known malicious extension ID blocklist
└── icons
```

## Installation

1. Clone the repository:
   ```bash
   git clone <repo-url>
   ```
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `guardext/` directory.

## Usage

1. Click the GuardExt icon in the toolbar.
2. Click **Scan Extensions**.
3. Review the results — each extension is listed with its risk level and reasons.

## Blocklist

The file `data/malicious_ids.json` contains entries in this format:

```json
[
  {
    "id": "extension-id-here",
    "name": "Extension Name",
    "reason": "Brief description of malicious behavior"
  }
]
```

To add an entry, append an object to the array and push to `main`. The GitHub Actions workflow will deploy the updated list to GitHub Pages automatically.

### Remote Blocklist (GitHub Pages)

The workflow at `.github/workflows/deploy-blocklist.yml` deploys `malicious_ids.json` to GitHub Pages on pushes to `main`. To enable it:

1. Go to your repo's **Settings > Pages**.
2. Set **Source** to **GitHub Actions**.
3. Set `REMOTE_BLOCKLIST_URL` in `background/background.js` to your Pages URL:
   ```
   https://<username>.github.io/<repo>/malicious_ids.json
   ```

The extension fetches the remote list first and falls back to the local copy if the fetch fails.

## Permissions

| Permission      | Purpose                                      |
|-----------------|----------------------------------------------|
| `management`    | Read metadata of all installed extensions     |
| `storage`       | Persist scan results (reserved for future use)|
| `alarms`        | Schedule periodic scans (reserved)            |
| `notifications` | Alert on newly detected threats (reserved)    |

## License

MIT
