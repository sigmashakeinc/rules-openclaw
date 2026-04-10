# rules-openclaw

OpenClaw governance rules — guards against the one-click RCE (CVE-2026-25253), 21,639 exposed public instances, the 820+ malicious ClawHub skills (7.7% malware rate), the March 2026 attack on 10 Mexican government agencies, and the full OpenClaw security surface: prompt injection, browser SSRF, credential harvesting, sandbox escape, control plane abuse, symlink attacks, and workspace boundary violations.

**51 rules · 8 files**

![rules-openclaw — AI agent governance demo](demo.cast)

> [▶ Watch interactive demo on SigmaShake Hub](https://hub.sigmashake.com/ruleset/rules-openclaw)

## Install

```bash
ssg hub pull rules-openclaw
```

Available on the [SigmaShake Hub](https://hub.sigmashake.com) — the open registry for AI agent governance rules. Compatible with any AI agent framework using the `ssg` hook protocol.

## Rules

### openclaw_exec_rce.rules — RCE and exposure prevention (8 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-url-param-injection` | DENY | error | CVE-2026-25253: Blocks URL params with shell metacharacters (one-click RCE) |
| `no-openclaw-skill-install` | DENY | error | Blocks skill installation from ClawHub (820+ malicious skills, 7.7% malware rate) |
| `no-openclaw-public-binding` | DENY | error | Blocks binding to 0.0.0.0/:: (21,639 exposed instances) |
| `ask-openclaw-network-access` | ASK | warning | Prompts before enabling network access flags |
| `log-openclaw-server-start` | LOG | info | Audit trail for all OpenClaw server invocations |
| `no-openclaw-system-run` | DENY | error | Blocks system.run on paired nodes (remote code execution) |
| `no-openclaw-sandbox-escape` | DENY | error | Blocks --privileged, --cap-add=ALL, --no-sandbox, --disable-seccomp flags |
| `no-openclaw-eval-injection` | DENY | error | Blocks eval(), new Function(), vm.run* in OpenClaw context |

### openclaw_exec_browser.rules — Browser control security (6 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-cdp-access` | DENY | error | Blocks CDP endpoint exposure (--remote-debugging-port/address) |
| `no-openclaw-credential-harvest` | DENY | error | Blocks browser navigation to credential managers and password stores |
| `no-openclaw-browser-ssrf-private` | DENY | error | Blocks browser SSRF to RFC 1918, loopback, and link-local addresses |
| `ask-openclaw-headless-browser` | ASK | warning | Prompts before headless browser execution (no visual audit trail) |
| `no-openclaw-browser-file-protocol` | DENY | error | Blocks file:// protocol in browser navigation (local filesystem read bypass) |
| `log-openclaw-browser-launch` | LOG | info | Audit trail for all OpenClaw browser tool invocations |

### openclaw_write_skill_safety.rules — Skill write safety (8 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-skill-shell-execution` | DENY | error | Blocks skills with subprocess/exec (primary malware mechanism) |
| `ask-openclaw-skill-network-access` | ASK | warning | Prompts on skills with HTTP requests (exfiltration risk) |
| `ask-openclaw-skill-filesystem-escape` | ASK | warning | Prompts on skills accessing absolute filesystem paths |
| `ask-openclaw-clawhub-publish` | ASK | warning | Prompts before publishing to ClawHub (7.7% malware rate) |
| `log-openclaw-skill-file-access` | LOG | info | Audit trail for all skill file reads |
| `no-openclaw-skill-prompt-injection` | DENY | error | Blocks injection markers in skill/config content (role-overriding phrases) |
| `no-openclaw-npm-lifecycle-scripts` | DENY | error | Blocks preinstall/postinstall/prepare hooks in skill package.json |
| `no-openclaw-skill-dynamic-require` | DENY | error | Blocks dynamic require(variable) and non-literal import() in skills |

### openclaw_read_secrets.rules — Secrets and sensitive file protection (7 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-read-config-tokens` | DENY | error | Blocks reads of ~/.openclaw/ config, credentials, auth-profiles, secrets.json |
| `no-openclaw-read-session-transcripts` | DENY | error | Blocks reads of session transcripts and conversation history |
| `no-openclaw-read-tool-output-files` | ASK | warning | Prompts before reading tool output dump files |
| `no-openclaw-read-ssh-keys` | DENY | error | Blocks reads of SSH private keys in OpenClaw context |
| `no-openclaw-read-cloud-credentials` | DENY | error | Blocks reads of AWS, GCP, Azure, kubeconfig credential files |
| `no-openclaw-read-browser-state` | DENY | error | Blocks reads of Chrome/Firefox Login Data, cookies, key4.db |
| `log-openclaw-state-file-access` | LOG | info | Audit trail for .state, .db, .sqlite, .jsonl, flight log access |

### openclaw_network_exposure.rules — Network exposure prevention (7 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-tunnel-exposure` | DENY | error | Blocks ngrok/Cloudflare tunnel exposure of OpenClaw |
| `no-openclaw-hardcoded-api-key` | DENY | error | Blocks hardcoded credentials in OpenClaw config files |
| `ask-openclaw-docker-deployment` | ASK | warning | Prompts on Docker deployments with OpenClaw |
| `log-openclaw-config-modification` | LOG | info | Audit trail for all OpenClaw config file changes |
| `no-openclaw-mdns-broadcast` | DENY | error | Blocks mDNS/Bonjour full advertisement of OpenClaw services |
| `no-openclaw-tailscale-funnel` | DENY | error | Blocks Tailscale Funnel exposure (public internet, not just Tailnet) |
| `no-openclaw-lan-binding` | DENY | error | Blocks binding to RFC 1918 LAN interfaces (192.168.x, 10.x, 172.16-31.x) |

### openclaw_write_policy.rules — Access policy and control plane safety (7 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-wildcard-group-allowlist` | DENY | error | Blocks wildcard '*' in group/DM allowlists (unrestricted tool access) |
| `no-openclaw-missing-mention-requirement` | ASK | warning | Prompts on group configs without requireMention: true |
| `no-openclaw-gateway-config-mutation` | DENY | error | Blocks persistent gateway config mutations (bind, auth, routes) |
| `no-openclaw-cron-tool-creation` | ASK | warning | Prompts before creating recurring scheduled tasks via cron tool |
| `no-openclaw-xforwarded-trust` | DENY | error | Blocks unsafe X-Forwarded-For trust without explicit IP allowlist |
| `no-openclaw-host-header-injection` | DENY | error | Blocks hostnames derived from HTTP Host header without validation |
| `log-openclaw-policy-file-write` | LOG | info | Audit trail for all OpenClaw policy and access control file changes |

### openclaw_exec_symlink.rules — Symlink attack prevention (3 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-symlink-to-config` | DENY | error | Blocks ln -s targeting OpenClaw config/state directories |
| `no-openclaw-symlink-to-secrets` | DENY | error | Blocks ln -s targeting SSH keys, cloud credentials, secret files |
| `log-openclaw-symlink-creation` | LOG | info | Audit trail for all symlink creation in OpenClaw context |

### openclaw_any_workspace.rules — Workspace boundary and container safety (5 rules)

| Rule | Decision | Severity | Description |
|------|----------|----------|-------------|
| `no-openclaw-cross-agent-read` | DENY | error | Blocks ../ path traversal escaping sandbox workspace scope |
| `no-openclaw-bind-mount-escape` | DENY | error | Blocks docker -v /:/host, /etc, /proc, /sys, docker.sock mounts |
| `no-openclaw-workspace-root-mount` | ASK | warning | Prompts on home directory or broad workspace root bind mounts |
| `ask-openclaw-privileged-container` | ASK | warning | Prompts on docker --privileged in OpenClaw context |
| `log-openclaw-workspace-boundary` | LOG | info | Audit trail for sandbox workspace boundary access |

## Coverage

| Attack Vector | Coverage | DSL Mechanism |
|---------------|----------|---------------|
| Prompt Injection | Full | `content LINE_REGEX` on write — injection markers, role-override phrases |
| Tool Authority Delegation | Full | `command REGEX` + `tool EQUALS` — exec/browser/file tool gating |
| Remote Code Execution | Full | `no-openclaw-system-run` + `no-openclaw-eval-injection` |
| Browser Control | Full | CDP, credential harvest, file://, SSRF, headless audit |
| Filesystem Access | Full | `path GLOB` on read — transcripts, state, output files |
| Plugin/Extension Code | Full | npm lifecycle, dynamic require, eval in skill context |
| Secrets on Disk | Full | Config tokens, SSH keys, cloud creds, browser state |
| Network Exposure | Full | Tunnel, mDNS, Tailscale Funnel, LAN binding |
| DM/Group Policy Bypass | Full | Wildcard allowlists, requireMention enforcement |
| Control Plane Tool Abuse | Full | Gateway config mutations, cron job creation |
| Symlink Attacks | Partial | Blocks `ln -s` commands; cannot detect pre-existing symlinks |
| Reverse Proxy Misconfig | Full | X-Forwarded-For trust, host-header injection |
| Sandbox Escape | Full | --privileged, --cap-add=ALL, --no-sandbox, bind mount escapes |
| Workspace Access | Full | Path traversal, bind mount escapes, root workspace mounts |
| Browser SSRF | Partial | RFC 1918 / loopback regex; decimal IP encoding / DNS rebinding not covered |
| Secret Rotation | None | Requires temporal logic (credential age) — out of DSL scope |

## Why this matters

OpenClaw is the fastest-growing AI agent tool in recent memory, with **135,000 GitHub stars in weeks** — and it's also the subject of the first major AI agent security crisis of 2026:

- **CVE-2026-25253** (Dark Reading/Censys): One-click RCE via the Control UI's trust of URL parameters without validation. A single malicious link achieves arbitrary code execution.
- **21,639 exposed instances** (Censys, 2026): More than 21,000 OpenClaw instances were found publicly accessible on the internet. The official docs acknowledge: *"there is no 'perfectly secure' setup."*
- **820+ malicious ClawHub skills** (security researchers): Out of 10,700 skills on ClawHub, 820+ were identified as malicious (7.7%), increasing from 324 in just weeks. Malicious skills achieved: data exfiltration, crypto-mining, and lateral movement.
- **Mexican government attack** (early March 2026): AI agents built on OpenClaw were used to compromise 10 government agencies and steal data on 100M+ citizens.
- **Moltbook breach** (Wiz Research): Moltbook (the social network built on OpenClaw) exposed 1.5M API tokens and 35,000 emails from misconfigured infrastructure.

## Compatible AI clients

- OpenClaw / ClawdBot / MoltBot instances
- Any autonomous AI agent framework
- Works alongside: `rules-security`, `rules-secrets`, `rules-docker`, `rules-moltbook`

## About

Part of the [SigmaShake Hub](https://hub.sigmashake.com) — open-source governance rules for AI coding agents.
Install the `ssg` CLI to enforce these rules: `npm install -g @sigmashake/ssg`
