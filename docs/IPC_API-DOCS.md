# IPC API Docs (Local iframe IPC)

## Overview
Provides a minimal, local-mode communication layer between `index.html` (parent) and embedded views (`explorer.html`, `stix-builder.html`) for:
- theme synchronization
- shared dataset handoff (`AF_SHARED_DATA`) to avoid redundant loading work

## Scope and Purpose
- Designed for local browser usage (`file://`) and controlled by configuration.
- Not intended as a general cross-origin API surface.
- IPC is restricted to embedded first-party frames used by AttackFlow.

## Architecture
- **Parent**: `index.html`
  - Owns canonical shared data cache.
  - Bootstraps one `MessageChannel` per iframe.
  - Generates per-session nonce and binds it to each iframe channel.
  - Applies bounded bootstrap timeout/retry/backoff and marks terminal retry exhaustion.
- **Children**: `explorer.html`, `stix-builder.html`
  - Accept channel bootstrap from parent.
  - Send typed requests over channel.
  - Apply validated responses.
- **Recovery**: Children maintain explicit bootstrap-failure handling without falling back to legacy request/response messaging.

## Message Types
Requests (child -> parent):
- `AF_REQUEST_THEME`
- `AF_REQUEST_SHARED_DATA` (explorer path)

Responses (parent -> child):
- `AF_THEME_SYNC`
- `AF_SHARED_DATA`

Bootstrap:
- `AF_IPC_PORT_INIT` (window message with transferred `MessagePort`, channel id, nonce)

## Security and Hardening
- Source pinning: only expected frame windows are accepted.
- Strict allowlists: message types and payload keys are validated; unknown keys/types are rejected.
- Nonce binding: channel messages must include correct session nonce.
- Immutable shared data: `AF_SHARED_DATA` is schema-checked, cloned, and deep-frozen.
- Iframe containment: iframe sandbox is enabled (`allow-scripts allow-same-origin allow-modals`).
- Request throttling: per-frame, per-request-type token-bucket limits (configurable).
- Channel-only transport: legacy window request/response IPC path removed.
- Bootstrap resilience: bounded timeout + retry/backoff with terminal failure signaling in child views.

## Threat Model (Local)
Defends against:
- unsolicited or malformed IPC messages
- accidental protocol misuse and message-spam loops
- over-privileged child access to parent state

Assumptions:
- attacker can potentially execute script in one frame context
- local-mode browser constraints apply (e.g., limited origin guarantees in `file://`)

## Configuration
In `config.js`:
- `CONFIG.ConfigIframeIPC.enableLocalIframeIPC`
- `CONFIG.debugging.traceLocalIframeIPCLogs`
- `CONFIG.debugging.localIframeIPCRateLimit.enabled`
- `CONFIG.debugging.localIframeIPCRateLimit.refillPerSecond`
- `CONFIG.debugging.localIframeIPCRateLimit.burst`
- `CONFIG.debugging.localIframeIPCBootstrap.timeoutMs`
- `CONFIG.debugging.localIframeIPCBootstrap.maxRetries`
- `CONFIG.debugging.localIframeIPCBootstrap.retryBaseDelayMs`
- `CONFIG.debugging.localIframeIPCBootstrap.retryBackoffMultiplier`
- `CONFIG.debugging.localIframeIPCBootstrap.maxRetryDelayMs`
- `CONFIG.debugging.localIframeIPCBootstrap.graceMs`
