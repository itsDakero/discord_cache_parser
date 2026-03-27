# Discord Cache Parser

Standalone Discord cache parser that extracts:

- message JSON cached by Discord
- cached attachments
- cached avatars
- a machine-readable `report.json`
- a browsable `index.html`

## Supported cache formats

- `OkHttp` caches used by Android-style clients
- Chromium `simple` cache format used by modern Chromium-based desktop clients
- Chromium `blockfile` caches when `ccl_chromium_reader` is installed separately

## Usage

```powershell
py .\discord_cache_parser.py `
  --input "C:\path\to\Cache" `
  --output "C:\path\to\discord-report"
```

## Output

- `report.json`: structured output for automation or downstream tooling
- `index.html`: human-readable report
- `attachments/`: extracted cached attachments
- `avatars/`: extracted cached avatars

## Notes

- `Brotli` is required for cache entries stored with `content-encoding: br`.
- For Chromium blockfile caches, install `ccl_chromium_reader` from https://github.com/cclgroupltd/ccl_chromium_reader/ and rerun the parser.
