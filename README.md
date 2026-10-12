<p align="center">
  <img src="assets/logo.jpg" width="220" alt="Red Wolf logo"/>
</p>

<h1 align="center">🐺 Red Wolf</h1>
<p align="center"><b>WOLF | RED WOLF</b></p>
<p align="center"><i>Unauthenticated Access Scanner</i></p>

<p align="center">
  <img src="assets/eye-wolf.jpg" width="600" alt="Eye Wolf identity artwork"/>
</p>

---

Red Wolf detects **Broken Access Control / Unauthenticated Access** to
API, admin, and file-download endpoints — generalized from the
real-world pattern reported against `equella.monash.edu` (a REST API,
admin pages, and file downloads all missing auth, plus a permissive
`Access-Control-Allow-Origin: *`) — then optionally hands the findings
to an AI model to write up the risk, severity, remediation, and a
submission-ready description.

> ⚠️ **Only run this against a target you are explicitly authorized to
> test** — a program in scope on HackerOne, Bugcrowd, Intigriti,
> YesWeHack, Inspectiv, or your own lab/infrastructure. The CLI
> refuses to run without `--i-am-authorized`.

## What it does

1. **Discovers endpoints** two ways at once:
   - From a file you supply (`--endpoints-file`), e.g. paths you found via Burp/recon.
   - From a built-in wordlist of common sensitive paths (`--wordlist`), e.g. `api/search`, `admin`, `.git/config`, `actuator/env`.
2. **Tests each one with a clean, unauthenticated session** — no cookies, no `Authorization` header, no redirects followed.
3. **Flags findings**: endpoints that responded 2xx/206 AND either leaked something sensitive or returned `Access-Control-Allow-Origin: *`.
4. **Deep probe (`--deep-probe`)**: recursively extracts file references from JSON responses and actually tries to download them unauthenticated — turning "metadata leaked" into a **confirmed** file download.
5. **AI-assisted analysis (`--ai-analyze`)**: sends a trimmed, structured summary of the findings to an LLM of your choice and gets back a risk narrative, a severity opinion, remediation steps, and a ready-to-paste submission paragraph.
6. **Smart scan ordering (`--smart-order`)**: uses **Red Wolf Optimization (RWO)** -- a Grey-Wolf-Optimizer-style meta-heuristic bundled in `rwo.py` -- to learn which endpoint category (API / Admin / File / Misc) to test first, cutting the expected number of requests before hitting a real finding by ~30% versus plain alphabetical order. See `smart_schedule.py`.
7. **Generates a report** (`--format md json html`) laid out like a bug bounty submission.
8. **Learns locally from previous scans**: with `--smart-order`, observed
   accessible/high-signal paths are ranked earlier on the next scan. Only
   hashed hosts, normalized path patterns, counters, and optional feedback
   labels are stored locally in `~/.red_wolf/learning.db`; response bodies,
   credentials, query values, and API keys are never stored.
9. **Automatically verifies candidate findings**: promising read-only
   responses are repeated, fingerprinted, checked for stable status/content,
   and screened for login-page markers before being reported as probable or
   confirmed.

Red Wolf's distinctive feature is its **Evidence-First Arrow** strategy:
discovered and candidate paths are ranked by observable signal before
requests are spent, while each accessible response receives a bounded
evidence score based on response structure, sensitive indicators, CORS, and
endpoint semantics. The score is a triage aid, not a claim of vulnerability
and never replaces manual verification.

The project includes a terminal-safe wolf identity and additional artwork in
`assets/`: `eye-wolf.jpg`, `wolf-shadow.jpg`, `logo.jpg`, and
`rwo_convergence.png`. The CLI prints the English Red Wolf identity and an
ASCII wolf when it opens; images are referenced in documentation and reports
without making terminal image rendering a dependency.

When the interactive wizard starts, it also opens the bundled
`assets/red_wolf_branding.html` locally in the default browser. This gallery
shows the Eye Wolf and Wolf Shadow artwork without contacting an external
website. The terminal displays an ASCII wolf so the identity is visible even
when no graphical browser is available.

## Install

```bash
pip install -r requirements.txt
```

For a packaged installation:

```bash
python -m pip install .
red-wolf --version
```

## Usage

### Option A -- Interactive wizard (no flags needed)

Just run it with no arguments (or `--interactive` / `-i`) and answer the
prompts -- it asks for the target, then walks you through every option
(manual endpoints file, wordlist, smart ordering, deep probe, AI
analysis, output format) and finally asks you to explicitly confirm
authorization before sending a single request:

```bash
python -m red_wolf.cli
```

### Option B -- Flags (scriptable, good for CI/automation)

```bash
python -m red_wolf.cli \
  --url https://target.example.com \
  --endpoints-file my_endpoints.txt \
  --wordlist \
  --deep-probe \
  --ai-analyze --ai-provider openrouter --ai-api-key sk-... \
  --format md json html \
  --output report \
  --i-am-authorized
```

### Key flags

| Flag | Meaning |
|---|---|
| `--url` | Base URL of the authorized target |
| target input | The interactive wizard also accepts a CIDR range such as `192.0.2.0/28` or a wildcard such as `*.example.com` |
| `--endpoints-file` | Text file, one path per line (manual/recon-sourced endpoints) |
| `--wordlist` | Also fuzz the built-in wordlist of common sensitive paths |
| `--custom-wordlist` | Use your own wordlist file instead of the built-in one |
| `--deep-probe` | Extract + verify real file downloads from JSON responses |
| `--smart-order` | Order the wordlist by RWO-learned category priority instead of alphabetical |
| `--methods` | HTTP methods to try per path; Enter, `all`, or `safe` in the wizard selects the complete safe set `GET,HEAD,OPTIONS` |
| `--profile` | `focused`, `balanced`, `full`, or `comprehensive`; the quick wizard defaults to `comprehensive` |
| `--no-discovery` | Disable same-origin discovery from `robots.txt`, sitemaps, and OpenAPI/Swagger documents |
| `--max-discovered` | Cap discovered paths per target (default: 100) |
| `--no-learning` | Disable the local adaptive history for this run |
| `--feedback-path` / `--feedback` | Label a path `useful` or `not-useful` to improve future ordering |
| `--ai-analyze` | Send findings to an LLM for analysis + write-up |
| `--ai-provider` | `openai`, `openrouter`, `nvidia`, or `custom` |
| `--ai-api-key` | Your own key (or set `RED_WOLF_AI_API_KEY` env var) |
| `--ai-model` | Override the default model for the chosen provider |
| `--ai-base-url` | Required when `--ai-provider custom` — any OpenAI-compatible endpoint |
| `--format` | `md`, `json`, `html` — any combination |
| `--i-am-authorized` | Required confirmation gate |
| `--interactive` / `-i` | Launch the interactive wizard instead of using flags |

### AI providers supported out of the box

| Provider | `--ai-provider` | Default model |
|---|---|---|
| OpenAI | `openai` | `gpt-4o-mini` |
| OpenRouter | `openrouter` | `stepfun/step-5-preview` |
| NVIDIA NIM | `nvidia` | `nvidia/llama-3.1-nemotron-70b-instruct` |
| Anything else (self-hosted, Groq, etc.) | `custom` + `--ai-base-url` | must pass `--ai-model` |

No key is ever stored by the tool — it's read once at runtime from
the flag or the environment variable.

AI requests are capped at 2,048 output tokens and are skipped when the scan
has no findings or confirmed downloads, so a clean scan does not consume
provider credits.

Quick interactive mode detects the AI provider from the key prefix:
`nvapi-` selects NVIDIA, `sk-or-` selects OpenRouter, and `sk-` selects
OpenAI. For a custom OpenAI-compatible API, set
`RED_WOLF_AI_PROVIDER=custom`, `RED_WOLF_AI_BASE_URL`, and optionally
`RED_WOLF_AI_MODEL` before starting the wizard. Quick mode uses only
read-oriented HTTP methods (`GET`, `HEAD`, and `OPTIONS`). Mutating methods
such as `POST`, `PUT`, `PATCH`, and `DELETE` must be passed explicitly with
`--methods` when they are authorized and required.

In the interactive wizard, pressing Enter at the HTTP methods prompt runs
the complete safe profile automatically. You can also type `all` or `safe`;
the parser accepts comma- or space-separated methods and ignores unknown
values instead of crashing.

During a scan the CLI displays a progress bar, completed request count,
current path and method, and an estimated time remaining. The built-in
wordlist includes API, admin, file, documentation, health, deployment, and
common metadata paths; use `--custom-wordlist` or `--endpoints-file` to add
target-specific paths beyond the built-in list.

The focused profile is the recommended default for reconnaissance: it tests
high-signal API, admin, file, configuration, and observability paths first
instead of spending time on generic low-value paths. Use `--profile full`
when broad coverage is more important than speed.

The `comprehensive` profile combines bounded same-origin discovery with the
full built-in path list. It reads HTML, JavaScript references, robots,
sitemaps, OpenAPI/Swagger, and GraphQL candidates, then caps discovery
documents and paths to avoid unbounded crawling. It does not attempt
state-changing requests automatically and cannot validate IDOR/business
logic without explicitly authorized test accounts.

Adaptive learning is deliberately local and bounded. A previous scan does
not grant authorization, prove a vulnerability, or replace verification.
To give explicit feedback after a run, use for example:

```bash
python -m red_wolf.cli --url https://target.example.com \
  --feedback-path api/items --feedback useful --i-am-authorized
```

Use `--no-learning` when a run must be completely stateless. The database
location can be changed with `RED_WOLF_LEARNING_DB`.

Candidate verification is enabled by default. It reduces transient and
generic-login false positives, but it cannot establish authorization scope,
business impact, or account-specific IDOR behavior from an anonymous
read-only request alone. Those are boundaries of HTTP evidence, not missing
automation.

Before probing the wordlist, the scanner performs bounded same-origin
discovery from `robots.txt`, `sitemap.xml`, `sitemap_index.xml`,
`openapi.json`, `swagger.json`, and `api-docs`. Discovered paths are tested
before generic paths and external hosts are ignored. This improves signal
without relying on third-party enumeration services.

CIDR expansion is capped at 256 hosts per input. Wildcard expansion uses a
bounded local list of common subdomain labels and DNS resolution; it is not
a complete subdomain enumeration. For complete authorized coverage, provide
an inventory through `--endpoints-file`.

## Red Wolf Optimization (RWO)

`rwo.py` implements a small Grey-Wolf-Optimizer-style meta-heuristic,
named after the tool, based on red wolf pack behavior:

- The pack's two best solutions so far (**alpha**, **beta**) act as leaders.
- A caution coefficient `A = 2*a*r1 - a` (with `a` decaying 2 -> 0 over
  iterations) controls whether the pack **explores** (`|A| > 1`, scatters
  to search new areas) or **exploits** (`|A| < 1`, converges on the
  best-known area) -- the same explore/exploit trade-off every
  real-world fuzzer and bug hunter faces.
- Every wolf updates its position toward the midpoint between the
  directions suggested by alpha and beta: `X(t+1) = (X1 + X2) / 2`.

It's a **generic numerical optimizer** (`rwo.minimize(fitness_fn, dim,
bounds)`), validated against the Sphere benchmark function in
`test_rwo_benchmark.py` (converges from ~11 to ~1e-14 in 60
iterations -- see `assets/rwo_convergence.png`).

`smart_schedule.py` is where it's put to work: it treats "which
endpoint category to scan first" as the thing to optimize, with
fitness = expected number of requests sent before hitting a real
finding (lower is better). On Red Wolf's own wordlist, RWO converges
to `api > file > admin > misc`, cutting the expected requests-to-first-finding
from ~28.7 to ~20.2 (**~30% fewer requests on average**) versus plain
alphabetical order -- see `--smart-order` above.

> The category-vs-vulnerability prior used for this (`VULNERABLE_PRIOR`
> in `smart_schedule.py`) is an **illustrative assumption**, not a
> measured statistic -- override it with real data for your target's
> stack if you have it.

## Using it as a library (for your dashboard/API project)

```python
from red_wolf import ScanConfig, UnauthAccessScanner, build_report_data, to_json

config = ScanConfig(
    base_url="https://target.example.com",
    endpoints=["api/search"],
    methods=["GET", "HEAD", "OPTIONS"],
)
scanner = UnauthAccessScanner(config)
results = scanner.run()
report = build_report_data(config.base_url, results)
print(to_json(report))
```

## Hosted service mode

The optional `red_wolf.service` module exposes a small FastAPI job API for a
server deployment:

```bash
export RED_WOLF_SERVICE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export RED_WOLF_ALLOWED_HOSTS="target.example.com"
uvicorn red_wolf.service:app --host 127.0.0.1 --port 8000
```

Production deployments should place it behind HTTPS and a reverse proxy.
Every request must use the service token, explicitly confirm authorization,
and target an exact host in `RED_WOLF_ALLOWED_HOSTS`. The service accepts only
`GET`, `HEAD`, and `OPTIONS`, runs jobs asynchronously, and isolates jobs by a
tenant derived from the token.

The service database stores job state, a host fingerprint, and redacted
results. It does not persist target URLs, response bodies, response headers,
credentials, or API keys. Tenant learning is isolated; the optional shared
learning signal contains only normalized path patterns and aggregate counters.
Do not enable wildcard host allowlists on a public server. Set
`RED_WOLF_SERVICE_DB` to a private volume and protect it with normal server
permissions and backups.

The service also exposes `/docs` for an interactive OpenAPI reference. Keep
that endpoint behind the same reverse proxy authentication as the API in
production.

The service rejects non-HTTPS targets, requires an exact allowlisted hostname,
resolves the hostname before queuing work, and rejects loopback, private,
link-local, multicast, reserved, unspecified, and cloud-metadata addresses.
This is a first barrier, not a substitute for network egress controls; deploy
the worker in a restricted network with no access to instance metadata.

Per-tenant job quotas are controlled by `RED_WOLF_MAX_JOBS_PER_WINDOW` and
`RED_WOLF_JOB_WINDOW_SECONDS` (defaults: 5 jobs per hour). A queued or running
job can be cancelled with `POST /v1/jobs/{job_id}/cancel`; cancellation
prevents a completed result from being published.

### Container deployment

Build and run the hardened non-root image:

```bash
docker build -t red-wolf:1.1.0 .
docker run --rm -p 127.0.0.1:8000:8000 \
  -e RED_WOLF_SERVICE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  -e RED_WOLF_ALLOWED_HOSTS="target.example.com" \
  -v red-wolf-data:/var/lib/red-wolf \
  red-wolf:1.1.0
```

Put TLS, rate limiting, and user authentication in front of the container.
The service token is an internal service credential, not a replacement for
per-user authentication.

Endpoints:

- `GET /healthz`
- `GET /readyz`
- `POST /v1/jobs`
- `GET /v1/jobs/{job_id}`
- `POST /v1/jobs/{job_id}/cancel`
- `POST /v1/feedback`

Job requests may include `excluded_paths`, an array of relative path
prefixes such as `/admin` or `/internal`. Excluded subtrees are skipped by
both manual/wordlist scanning and discovery. Responses and deep-probe
downloads are bounded to prevent an authorized scan from consuming
unbounded memory or storage.

## Testing

Run the focused service safety tests with:

```bash
python -m pytest tests -q
```

The suite covers blocked network addresses, HTTPS and allowlist validation,
and tenant job quotas. Add a local mock target before exercising the scanner
itself; never use a public target as a test fixture.

`/healthz` is a liveness check. `/readyz` additionally requires service
authentication and at least one configured target host.

```bash
python test_vuln_app.py &
python test_mock_ai_server.py &

python -m red_wolf.cli --url http://127.0.0.1:5055 \
  --endpoints-file test_endpoints.txt --deep-probe \
  --ai-analyze --ai-provider custom --ai-base-url http://127.0.0.1:5056/v1 \
  --ai-api-key fake-key --ai-model test-model \
  --format md --output demo_report --i-am-authorized --delay 0
```

## Notes / limitations

- The "sensitive data", VRT, priority, and AI severity classifications
  are all **heuristics/opinions** — always manually verify before
  submitting a report.
- The default wordlist is generic on purpose. Add product-specific
  paths via `--custom-wordlist` per target instead of hardcoding them.
- This tool does not enforce platform scope itself — confirming scope
  is on you before you run it.
- The SQLite worker recovers safely after a restart by marking interrupted
  jobs as failed with a `service_restarted` audit event. It does not resume
  interrupted scans; use a durable queue for multi-process or high-volume
  deployments.
- The AI module sends only a trimmed JSON summary (URLs, status codes,
  flags) to the provider you choose — never raw file contents.
