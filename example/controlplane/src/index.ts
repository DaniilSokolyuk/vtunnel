/**
 * vtunnel controlplane example
 *
 * The sandbox has vtunnel server with MITM proxy. When code inside does
 * `https://api.anthropic.com/...` or `git clone https://github.com/...`,
 * the MITM proxy intercepts TLS, decrypts, and routes through the tunnel
 * to this controlplane as plain HTTP.
 *
 * This example returns mock responses to demonstrate credential injection
 * without requiring real API keys. In production, you'd inject real
 * credentials and forward to the actual upstream.
 *
 *   Sandbox Container                        Controlplane (this process)
 *   ┌──────────────────────┐                ┌─────────────────────────────┐
 *   │                      │                │                             │
 *   │ HTTPS_PROXY=:9090    │     TUNNEL     │ vtunnel client              │
 *   │ vtunnel server :3001 │◀══════════════▶│   ├─ api.anthropic.com     │
 *   │   + proxy :9090      │                │   └─ github.com            │
 *   │   + mitm ca.pem      │                │                             │
 *   └──────────────────────┘                └─────────────────────────────┘
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { spawn, ChildProcess } from "node:child_process";

// --- Config ---

const VTUNNEL_KEY = process.env.VTUNNEL_KEY;
const SANDBOX_WS_URL = process.env.SANDBOX_WS_URL || "ws://localhost:3001/";

const ANTHROPIC_PROXY_PORT = 8081;
const GITHUB_PROXY_PORT = 8082;

// --- Main ---

async function main() {
  await Promise.all([startAnthropicProxy(), startGitHubProxy()]);

  const vtunnel = startVtunnelClient();

  process.on("SIGINT", () => { vtunnel.kill(); process.exit(0); });
  process.on("SIGTERM", () => { vtunnel.kill(); process.exit(0); });

  console.log("[controlplane] ready — run test.sh from the sandbox to verify");
}

main();

// --- Anthropic Proxy (:8081) ---
// In production: inject x-api-key, forward to https://api.anthropic.com
// Here: return a mock response showing the injection point.

function startAnthropicProxy(): Promise<void> {
  return new Promise((resolve) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      console.log(`[anthropic-proxy] ${req.method} ${req.url}`);
      console.log(`[anthropic-proxy] would inject x-api-key: sk-ant-***`);

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        id: "msg_mock",
        type: "message",
        role: "assistant",
        content: [{ type: "text", text: "Hello from mock! In production, this request would have x-api-key injected and be forwarded to api.anthropic.com" }],
        model: "claude-sonnet-4-20250514",
        _vtunnel: {
          injected: "x-api-key",
          upstream: "https://api.anthropic.com" + req.url,
          original_headers: req.headers,
        },
      }));
    });

    server.listen(ANTHROPIC_PROXY_PORT, () => {
      console.log(`[anthropic-proxy] listening on :${ANTHROPIC_PROXY_PORT}`);
      resolve();
    });
  });
}

// --- GitHub Proxy (:8082) ---
// In production: inject Authorization header with PAT, forward to https://github.com
// Here: return a mock response showing the injection point.

function startGitHubProxy(): Promise<void> {
  return new Promise((resolve) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      console.log(`[github-proxy] ${req.method} ${req.url}`);
      console.log(`[github-proxy] would inject Authorization: Basic <base64(x-access-token:ghp_***)>`);

      // git clone hits /org/repo.git/info/refs?service=git-upload-pack first
      if (req.url?.includes("/info/refs")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("# mock git response — in production, PAT would be injected and forwarded to github.com\n");
        return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        message: "Hello from mock! In production, this request would have Authorization injected and be forwarded to github.com",
        _vtunnel: {
          injected: "Authorization: Basic <PAT>",
          upstream: "https://github.com" + req.url,
          original_headers: req.headers,
        },
      }));
    });

    server.listen(GITHUB_PROXY_PORT, () => {
      console.log(`[github-proxy] listening on :${GITHUB_PROXY_PORT}`);
      resolve();
    });
  });
}

// --- vtunnel client ---

function startVtunnelClient(): ChildProcess {
  const args = ["client", "-server", SANDBOX_WS_URL];

  if (VTUNNEL_KEY) {
    args.push("-key", VTUNNEL_KEY);
  }

  // Domain forwards: sandbox MITM proxy → tunnel → controlplane HTTP service
  args.push("-forward", `api.anthropic.com=localhost:${ANTHROPIC_PROXY_PORT}`);
  args.push("-forward", `github.com=localhost:${GITHUB_PROXY_PORT}`);

  console.log(`[vtunnel] starting: vtunnel ${args.join(" ")}`);
  const child = spawn("vtunnel", args, { stdio: "inherit" });

  child.on("error", (err) => {
    console.error(`[vtunnel] failed to start:`, err);
    process.exit(1);
  });

  return child;
}
