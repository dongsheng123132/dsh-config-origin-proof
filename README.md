# DSH Config Origin Proof

An evidence layer for [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) configuration source ownership. It verifies an explicit redacted recording of precedence domains, source observations, the expected winning source and value digest, shadowed sources, and unobserved higher-priority gaps.

It does **not** reimplement the DSH composer, collect live configuration, or compare policy changes. DSH's own `--dump-config` remains the authority for composition. This plugin turns a structured recording from that or another trusted producer into a reproducible receipt. `dsh-policy-drift-proof` compares baseline and observed policy posture; `dsh-profile-lock-proof` proves installed bundle closure; this project answers which recorded source won and why.

Raw values and secret-, credential-, prompt-, message- or prose-shaped fields are rejected. Reports contain only stable IDs, SHA-256 digests and verdicts. The verifier fails closed when a higher-priority source is unobserved.

## Surfaces

- DSH: `dsh_config_origin_inspect`, `dsh_config_origin_verify`.
- CLI: `dsh-config-origin-proof verify --workspace-root examples --recording recording.json --artifact-dir artifacts`.
- MCP: `config_origin_inspect_inline`, `config_origin_verify_inline`; inline-only, no filesystem, network, process or artifact writes.

```sh
dsh plugin --profile web add github:dongsheng123132/dsh-config-origin-proof
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
```

The ordering in `examples/recording.json` follows DSH's published configuration-source ownership contract, but the recording is explicit and revision-bound so a future DSH change cannot silently rewrite old evidence.

MIT
