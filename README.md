# Discord Cache Parser

Standalone Discord cache parser that extracts:

- message JSON cached by Discord
- cached attachments
- cached avatars
- a machine-readable `report.json`
- a Discord-style conversation view in `index.html`
- the original evidence tables in `evidence.html`

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
- `index.html`: dark conversation view with channel navigation, avatars, date separators,
  grouped messages, cached image previews, and expandable message metadata
- `evidence.html`: original tables, including participants and unassociated cached files
- `attachments/`: extracted cached attachments
- `avatars/`: extracted cached avatars

## Notes

- `Brotli` is required for cache entries stored with `content-encoding: br`.
- For Chromium blockfile caches, install `ccl_chromium_reader` from https://github.com/cclgroupltd/ccl_chromium_reader/ and rerun the parser.

## Conversation view

Keep `report.html` beside `discord_cache_parser.py` when copying the parser. Generated
reports are self-contained: copy the whole output directory, then open `index.html`
in a modern browser (channel switching uses CSS `:has()`, without JavaScript).
The view adapts to smaller screens; printing includes all channels.

Only extracted files load in the conversation view; missing attachments are labelled
"not cached". Other attachment formats have download links. No remote Discord media
or fonts are fetched. The evidence view retains original URLs as escaped text.

The cache is a partial reconstruction, not a screenshot of the original account.
Channel IDs stand in for names; server layout, account perspective, reply previews,
reactions, embeds, role colours, and permissions are not reconstructed. Cached message
variants may appear more than once. Timestamps use UTC, rather than guessing the
original user's timezone. Message details retain the original timestamp and IDs.

Formatting supports basic bold, italic, underline, strikethrough, inline/fenced code,
and user mentions resolved from recovered channel participants. Nested Markdown and
other Discord syntax remain approximate or literal; raw content stays in `report.json`
and the evidence view. Extraction and the JSON schema are unchanged.

Run the synthetic report tests (no evidence or real cache required):

```sh
python3 -m unittest discover -s forensics/discord-cache-parser/tests -v
```

## License

MIT, see `LICENSE`.
