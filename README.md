# Agentic Commerce Protocol (ACP) — `dev.mcpg.payment.acp`

> class `tool_gate` · `native` · package `mcpg-plugin-payment-acp` · artifact `libmcpg_plugin_payment_acp.so` · BUSL-1.1

Commerce gate that lets an MCP agent buy from merchants implementing the Agentic
Checkout specification. When a purchasing tool is called, the plugin opens a
checkout session against the merchant's ACP endpoint, hands the agent the
merchant's session state and payment handlers as an HTTP 402 challenge, and lets
the tool run only once the merchant reports the checkout settled. Reach for it
when a tool represents a real purchase from an ACP merchant and you need the
gateway — not the agent — to hold the merchant credential and to decide what
counts as paid.

## What it does
- Gates only the tools named in its `tools` map, and only on the tool surface.
  Everything else passes through untouched.
- Opens a checkout session on the first unpaid call by POSTing to
  `<merchant_base_url>/checkout_sessions`, then answers `Challenge` — HTTP 402,
  JSON-RPC code `-33055` — carrying the merchant's session, its available payment
  handlers, and any 3D Secure metadata.
- Resumes from `_meta["acp/checkout_session"]` on subsequent calls, completing
  the checkout at `<base>/checkout_sessions/<id>/complete` once the agent
  supplies `_meta["acp/payment_data"]`.
- Grants the call **only** when the merchant reports status `completed`, and
  returns the merchant's order object as decision metadata under `acp/order`.
- Re-challenges rather than allowing whenever the merchant reports 3D Secure is
  required, reports any other status, or fails the completion outright.
- Binds each session to the principal that created it, so one caller cannot
  address another's checkout by guessing its id.
- Speaks the ACP HTTP conventions on every merchant call: `Authorization:
  Bearer`, `API-Version`, `Idempotency-Key`, and `Content-Type:
  application/json`. The completion key is stable per session, so a retried
  completion replays rather than charging twice.
- Declares the `network_outbound` capability, consumed by the merchant calls.

## Configuration
Loaded from the flat top-level `plugins:` list. The `config:` block has two
halves: a `config` sub-object for protocol-wide settings, and a `tools` map whose
keys are the tool names to put behind checkout. With no `tools` entries the
plugin loads disabled and allows every call.

```yaml
plugins:
  - id: dev.mcpg.payment.acp
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_payment_acp.so }
    # or, platform-agnostic — the gateway resolves the artifact for its own
    # os/arch/libc at boot:
    # source: { oci: ghcr.io/mcpg-dev/source-code/plugins/payment-acp:protocol-1 }
    granted_capabilities: [network_outbound]   # required — the merchant calls
    config:
      config:
        default_api_version: "2026-01-30"
        session_ttl_ms: 3600000        # 1 hour
        http_timeout_ms: 30000
      tools:
        store.buy:
          merchant_base_url: https://merchant.example/agentic_commerce   # required
          auth_token: ${env.ACP_MERCHANT_TOKEN}                          # required
          agent_capabilities:
            interventions:
              supported: ["3ds"]
              display_context: webview
```

Protocol settings, under `config.config`:

| Field | Type | Default | Description |
|---|---|---|---|
| `default_api_version` | string | `"2026-01-30"` | Value sent in the `API-Version` header when a tool does not override it. |
| `session_ttl_ms` | integer | `3600` | Checkout-session lifetime in milliseconds. Past it the session is dropped and the call denied with HTTP 410. Set this to the real window you want to give an agent — the default is under four seconds. |
| `http_timeout_ms` | integer | `30` | Merchant request timeout, in milliseconds. Set this to a realistic value for your merchant — the default is 30 milliseconds. |
| `max_retries` | integer | `3` | Accepted by the schema. Merchant calls are issued once; a 409 or 5xx surfaces as a failure rather than being retried in-plugin. |
| `signing_key_env` | string | unset | Accepted by the schema. Requests are not JWS-signed. |

Per-tool settings, under `config.tools.<tool name>`:

| Field | Type | Default | Description |
|---|---|---|---|
| `merchant_base_url` | string | required | ACP checkout base URL. Must be non-empty. |
| `auth_token` | string | required | Bearer token for the merchant. Must be non-empty. |
| `api_version` | string | unset | Overrides `default_api_version` for this tool. |
| `agent_capabilities` | object | unset | Declared to the merchant at session creation as `capabilities.interventions`: `supported` (string array, e.g. `["3ds"]`) and `display_context` (default `"webview"`). |
| `enable_delegate_payment` | bool | `false` | Accepted by the schema; the delegate-payment flow is not driven by the plugin. |
| `item_mapping` | JSON | unset | Sent verbatim as the session's `items`. When unset, non-empty tool arguments are sent as `tool_arguments` instead. |

Unknown fields are rejected, at the wire level and inside both nested blocks.

The plugin declares the `network_outbound` capability, so the entry has to grant
it: a packaged load (`source.path` pointing at a `.zip`, or `source.oci`) is
refused at boot when `granted_capabilities` does not list it.

**Credential handling.** Write `auth_token` as a `${env.VAR}` interpolation or an
`env://VAR` / `file://path` secret reference. The gateway resolves both to a
literal value at config load, before the plugin sees the config, so the merchant
secret never has to live in the plugin's YAML.

## Operations
The agent drives the whole checkout through MCP `_meta`:

| Key | Direction | Meaning |
|---|---|---|
| `acp/checkout_session` | client → gateway | The merchant session id to resume. Absent means "open a new one". |
| `acp/payment_data` | client → gateway | The payment instrument and billing details to complete with. |
| `acp/authentication_result` | client → gateway | The 3D Secure result, forwarded to the merchant on completion. |
| `acp/update` | client → gateway | Read but not applied — the gate re-challenges with the last known merchant state. |
| `acp/order` | gateway → client | The merchant's order object, returned on the allowed call. |

A typical exchange is: call the tool with no session, receive a 402 with the
merchant session; complete the merchant-side steps; call again with
`acp/checkout_session` plus `acp/payment_data`; receive either the allowed tool
result with `acp/order`, or another 402 asking for 3D Secure.

## Security
**Settlement is proved, not assumed.** A non-error HTTP response from the
merchant is not treated as payment. Only status `completed` grants the call —
`ready_for_payment`, `in_progress`, `not_ready_for_payment`, `canceled`, and a
missing status all re-challenge. The order metadata is built from the merchant's
own `order` object; when it is absent the gate emits a bare session reference
rather than inventing a success receipt.

**Sessions are owned.** Each session is stamped with an ownership key derived
from the caller's subject and issuer, falling back to the MCP session id for
anonymous callers. A caller presenting someone else's session id is refused with
a "not found" shaped denial, so session existence is not leaked to a non-owner.

**Responses from private addresses are refused.** Every merchant response passes
a DNS-rebinding check that rejects a reply arriving from a private or loopback
address.

**Config failure modes are asymmetric — know which one you are in.** Malformed
JSON, an unknown key, or a `tools` entry that omits `merchant_base_url` or
`auth_token` refuses the plugin at boot, so a typo cannot open the gate. An empty
or absent `config:` block, a block with no top-level `config`, and
a structurally valid block that fails validation (an empty `merchant_base_url` or
`auth_token`) all load the plugin **disabled** — which allows every call. Treat a
startup log line naming a disabled payment gate as a production incident, and
assert on it in deployment checks.

**Sessions live in the process.** Checkout state is held in the plugin instance,
so an agent must return to the same gateway replica to complete a checkout, and a
restart invalidates open sessions.

**Error codes stay clear of the MCP reserved range.** `-33055` (checkout
required — also the code on the re-challenge after an unsettled or failed
completion), `-33056` (session creation failed), and `-33057` (session missing or
expired) sit outside `-32099..=-32000`.

## Observability
- `mcpg_payment_acp_evaluations_total{outcome}` — `allow`, `deny`, `challenge`,
  or `pending_approval`.
- `mcpg_payment_acp_evaluate_ms` — pre-dispatch evaluation latency.

Each evaluation opens an `acp_payment_evaluate_pre` tracing span tagged with the
plugin id and tool name. Session creation and completion log at INFO; idempotent
replays, ownership refusals, and unsettled completions log at WARN.

## Build
The `cdylib-export` feature gates the `mcpg_plugin_register` export. It is on by
default for a standalone build and switched off when the crate is linked as a
path dependency alongside other plugins, since several `mcpg_plugin_register`
symbols collide at link time:

```bash
cargo build -p mcpg-plugin-payment-acp --features cdylib-export --release   # → target/release/libmcpg_plugin_payment_acp.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, loading, and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling payment gates: `libs/plugins/payment/ucp`, `libs/plugins/payment/x402`,
  `libs/plugins/payment/mpp`
- Licence: BUSL-1.1 — see [`LICENSE`](./LICENSE) for the Additional Use Grant
  that governs production use.
