# sealform

[日本語](README.md)

**Encrypt web form input in the browser — with hybrid post-quantum encryption — before it is sent.**
Your server, database, logs and CDN only ever see ciphertext. Only the people holding the private keys can read it.

```html
<script src="/sealform.js" integrity="sha384-..." crossorigin="anonymous" defer></script>

<form method="post" action="/contact" enctype="multipart/form-data"
      data-sealform-key="/.well-known/sealform-key.json">
  <textarea name="message" data-seal></textarea>          <!-- encrypted -->
  <input type="file" name="attachment" data-seal>         <!-- attachments too -->
  <p data-sealform-status></p>
  <button type="submit" disabled data-sealform-submit>Send</button>  <!-- stays disabled until JS is ready -->
</form>
```

> Status: v0.3, experimental. It has **not** been reviewed by an independent cryptographer yet. It is not on npm yet: clone the repository and run `npm install && npm run build` (read `npx sealform` below as `node dist/cli.js`). Read "What it does not protect against" below before using it for sensitive data.

## Why

HTTPS only protects data in transit. The moment a submission reaches your server it is plaintext again, and it spreads into databases, access logs, error trackers, backups, CDNs and WAFs.
For counselling services, whistleblowing channels, job applications or medical questionnaires, a single leak of any of those is serious.

With sealform the server **never touches the plaintext**. If the server is breached, the attacker only finds ciphertext.

## Features

| | |
|---|---|
| **Hybrid post-quantum** | HPKE (RFC 9180) with X-Wing (X25519 + ML-KEM-768). Secure as long as either part holds, including against "harvest now, decrypt later". |
| **Drop-in** | One script tag and a few attributes. Ciphertext is sent under the original field names, so server code barely changes. |
| **Fail-closed** | If JavaScript is disabled, the key cannot be loaded or encryption fails, the form **cannot be submitted at all**. It never falls back to plaintext. |
| **Multiple recipients** | Every counsellor reads with their own private key. Losing one key does not lock the others out. |
| **Attachments** | File contents, original file names and MIME types are encrypted; sizes are padded to 4 KB. |
| **Key rotation** | Add a new key, remove the old one. Keep the old private key to read past submissions. |
| **Tamper detection** | The destination form and field name are bound to the ciphertext, so swapped or replayed ciphertext is rejected on decryption. |
| **External monitoring** | `sealform check` verifies from outside that the served JavaScript is byte-identical to an official release and that the public keys have not been swapped. |
| **Offline decryption** | The decryption tool for staff is a single HTML file whose CSP blocks all network access. |
| **Paper recovery codes** | Print a private key as a checksummed code and keep it in a safe. |
| **Server integrations** | Examples for Node, Express, Next.js, Flask and PHP, plus a WordPress (Contact Form 7) plugin. |

## Usage

### 1. Create keys (on each recipient's own machine)

```bash
npx sealform keygen --label "Counsellor A"
npx sealform keys add sealform-key.json sealform-key-<kid>.json ...   # collect the public keys into a key set
```

- `sealform-key.json` (key set) → publish at `/.well-known/sealform-key.json`
- `sealform-private-key-<kid>.json` (passphrase-protected) → **never put it on the server**
- Note the fingerprints (`SHA256:...`) printed by `keys add` / `keys list`

### 2. Add it to your form

Use the HTML above. Rules:

- `method="post"` is required (with GET the ciphertext would end up in URLs and logs, so sealform refuses).
- Mark the submit button `disabled data-sealform-submit` so nothing can be sent before encryption is ready.
- Only fields with `data-seal` are encrypted. Without any `data-seal`, every non-hidden field (including files) is encrypted.
- Encrypting files requires `enctype="multipart/form-data"`. The limit is 50 MB; lower it with `data-sealform-max-mb="10"`.
- Pin all recipients' fingerprints with `data-sealform-fingerprint="SHA256:... SHA256:..."`. If an unknown key appears in the key set, the form refuses to send.
- Pages with `<html lang="en">` (or `data-sealform-lang="en"`) show English messages.
- With React and similar, add `data-sealform-manual` and call `sealform.attach(form)` after rendering ([Next.js example](examples/nextjs/app/sealed-form.tsx)).

`npx sealform sri` prints the value for `integrity`.

### 3. On the server

Store what you receive. Use `isSealed()` / `isSealedFile()` to reject plaintext that should not be there. The same checks exist for PHP (`server/php/sealform.php`) and Python (`server/python/sealform_check.py`). Working examples are in [examples/](examples/README.md).

```js
import { isSealed, isSealedFile } from "sealform";
if (!isSealed(form.get("message"))) return new Response("not encrypted", { status: 400 });
```

### 4. Decrypt (on a recipient's machine)

```bash
npx sealform open --key sealform-private-key-<kid>.json --form /contact --out ./decrypted submissions.csv files/*.sf
```

Paste CSVs or whole emails; tokens starting with `sf2.` (or `sf1.`) are picked up automatically. Non-technical staff can use `dist/sealform-opener.html` instead.

### 5. Monitor from outside

```bash
npx sealform check https://example.org/contact --fingerprint "SHA256:... SHA256:..."
```

Exits with status 1 on problems. See the [GitHub Actions example](examples/github-actions/sealform-check.yml) for running it hourly.

### Paper recovery and key rotation

```bash
npx sealform recovery export sealform-private-key-<kid>.json   # printable HTML
npx sealform recovery import                                    # rebuild the key file from the paper code

npx sealform keys add sealform-key.json sealform-key-<new kid>.json
npx sealform keys remove sealform-key.json <old kid>
npx sealform open --key new.json --key old.json submissions.csv
```

A recovery code **is** the private key, without a passphrase. Store the paper somewhere locked.

## Threat model

### Protects against

- Server or database compromise, leaked backups
- Plaintext ending up in access logs, error trackers or analytics
- Your CDN, WAF or hosting provider reading submissions
- Future decryption by quantum computers (hybrid KEM)
- Modified ciphertext, ciphertext moved to another form or field, stripped recipients
- An attacker adding their own key to the key set to receive copies (when fingerprints are pinned)

### Does not protect against

- **An attacker who controls your server and changes the JavaScript or page itself.** This is a limitation of all in-browser end-to-end encryption. sealform helps you *detect* it (SRI, CSP, fingerprint pinning, and `sealform check` run from elsewhere), but cannot prevent it.
- Malware on the user's device or malicious browser extensions
- Compromise of a recipient's device or private key
- Metadata: that something was sent, when, its approximate size, and which key IDs it was addressed to

## Development

```bash
npm install
npm run build
npm test
npm run example   # demo at http://localhost:8787
```

- Wire format: [docs/FORMAT.md](docs/FORMAT.md) (Japanese)
- Test vectors: `test-vectors/` (X-Wing official vectors, sealform decryption vectors, server validator vectors)
- Reporting vulnerabilities: [SECURITY.md](SECURITY.md)

## License

Apache-2.0
