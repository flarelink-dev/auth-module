# Security Policy

## Reporting a vulnerability

Email **hello@flarelink.dev** with `[SECURITY]` in the subject. Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected component and version — for the auth Worker, the version reported at `GET <your-worker>/__flarelink`.

We'll acknowledge your report, keep you updated as we investigate, and credit you if you'd like. Please give us a reasonable window to ship a fix before public disclosure.

## Scope

This repo is the **auth Worker** (source-available, FSL-1.1-MIT) that Flarelink deploys onto customers' own Cloudflare accounts. Auth, session handling, password hashing, OAuth, email flows, and the storage/db routes are all in scope.

## Verify what's deployed

The bundle is reproducible from this source and its SHA-256 is published in [`HASHES.md`](HASHES.md). Confirm that the Worker running in your account matches the published bundle:

```
npx @flarelink/verify --url https://your-auth-worker.workers.dev
```

More at <https://flarelink.dev/trust>.
