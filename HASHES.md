# Published bundle hashes

SHA-256 of `dist/worker.mjs` for each released `FLARELINK_AUTH_VERSION`. This is
the exact bundle Flarelink uploads to your Cloudflare account.

You can verify two things against this table:

1. **What's deployed in your account matches what Flarelink published.** Pull the
   deployed script with your own CF token and hash it — see [README → Verify the
   deployed bundle](README.md#verify-the-deployed-bundle), or run
   `npx @flarelink/verify` which does it for you.
2. **What Flarelink published matches this public source.** Clone this repo at the
   matching `v<version>` tag, run `npm ci && npm run build`, and hash the output.
   It reproduces the bundle byte-for-byte.

```
shasum -a 256 dist/worker.mjs        # macOS / Linux
sha256sum dist/worker.mjs            # Linux
```

| Version | git tag | SHA-256 of `dist/worker.mjs` |
|---------|---------|------------------------------|
| 0.3.2   | `v0.3.2` | `e2c1c30319a21c30511c9e293b2a78da628a93e5ebd4ca4793d9c9ac1d88db3e` |
| 0.3.1   | `v0.3.1` | `a95e056a7c1c6c036a1e7b97029602b886b80ade97465dcbb6398d55d28f198f` |
| 0.3.0   | `v0.3.0` | `06c3ded7f856061c3c70ba6ea7a7bd87d3a8f3593075cee079df0a7f089ed6c9` |

> Reproducibility depends on the pinned toolchain: exact dependency versions in
> `package-lock.json` and esbuild's deterministic output. Build with the Node
> version in `.github/workflows/release.yml`. A mismatch means the bytes differ —
> which is exactly the signal this table exists to surface.
