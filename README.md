# Discord Cache Parser

Standalone Discord cache parser that extracts:

- message JSON cached by Discord
- cached attachments
- cached avatars
- a machine-readable `report.json`
- a browsable `index.html`

## Supported cache formats

- Chromium `simple` and `blockfile` caches (desktop clients), parsed via [`ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chromium_reader)'s `ccl_chromium_cache` module
- `OkHttp` caches (Android clients), parsed by this tool directly since `ccl_chromium_cache` does not read that format

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

- Install dependencies with `pip install -r requirements.txt`. `ccl_chromium_reader` is required; `Brotli` is needed for entries stored with `content-encoding: br`.
