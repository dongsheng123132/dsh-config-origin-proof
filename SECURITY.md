# Security

DSH Config Origin Proof validates explicit, value-redacted recordings. It rejects raw-value, credential, prompt, message and prose-shaped fields. Reports contain only stable IDs, SHA-256 digests, source metadata and verdicts.

The DSH/CLI surface reads one bounded workspace-relative regular file, rejects traversal and symlinks, and writes only beneath an explicit workspace-relative `artifactDir` with content addressing and read-back verification. The MCP surface accepts bounded inline JSON only and performs no filesystem, network or child-process operation. The plugin never discovers or reads live credentials.

Report vulnerabilities through GitHub Security Advisories without including credentials or private configuration values.
