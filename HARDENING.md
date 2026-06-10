# Hardened fork notes

Private, security-hardened fork of OpenSnitch for an internal Debian 13
(trixie) workstation. This file documents the delta from upstream and the
steps required to deploy it safely. Track upstream `master` closely and keep
this delta small; upstream what you can.

## Threat model

OpenSnitch's daemon runs as root, parses hostile network data, and is the
control that decides what leaves the machine. The two failure modes that
matter:

1. **Bypass** — the firewall silently stops enforcing (fail open).
2. **Privilege escalation / MITM** — a local process subverts the
   daemon<->GUI channel or the daemon itself.

The changes below close the defaults that made those easy.

## Delta from upstream

### 1. Netfilter packet path fails closed instead of crashing
`daemon/netfilter/queue.{h,go}`

The kernel->userspace callback had unguarded conditions (NULL packet header,
non-positive payload length, empty verdict packet) that would segfault/panic
the daemon. With the upstream default `QueueBypass: true`, a daemon crash lets
all traffic through. We now NULL/length-check and **drop** unreadable packets.

### 2. UI channel is mTLS-only by default
`daemon/ui/auth/auth.go`, `daemon/data/default-config.json`

Upstream's shipped `/etc` config used `Authentication.Type: "simple"` —
no TLS, no authentication — over a world-writable `/tmp` socket. `auth.New()`
now **refuses** `simple`/empty auth unless `OPENSNITCH_ALLOW_INSECURE_UI=1`
is set, and the default config uses `tls-mutual` with certs under
`/etc/opensnitchd/certs`.

### 3. Firewall fails closed
`daemon/data/default-config.json`: `QueueBypass: false`

If the daemon is not consuming the nfqueue (crash, restart, stop), packets are
**dropped**, not accepted. Trade-off: while the daemon is down the workstation
has no network. The systemd unit uses `RestartSec=1` to keep that window tiny.

### 4. UI socket off `/tmp`
`daemon/data/default-config.json`: `unix:///run/user/1000/opensnitch/osui.sock`

The socket is created by the **unprivileged GUI**, not the daemon, so it lives
in your per-user runtime dir (`/run/user/<uid>`, mode `0700`) — not
world-writable `/tmp`. The root daemon dials it. **Replace `1000` with your
actual UID** (`id -u`).

### 5. Hardened systemd unit
`utils/packaging/daemon/deb/debian/opensnitch.service`

`NoNewPrivileges`, `RestrictSUIDSGID`, `RestrictRealtime`, `LockPersonality`,
`ProtectControlGroups`, fast restart. Stricter confinement
(`ProtectSystem=strict`, `CapabilityBoundingSet`, `MemoryDenyWriteExecute`,
`ProtectHome`) is left commented out because it can break eBPF loading, `/proc`
inspection, rule writes, or binary-checksum reads under `/home` — enable and
test on the target before rollout.

### 6. CI
`.github/workflows/hardened-ci.yml`

Builds in a `debian:trixie` container, runs `go vet`/tests, `govulncheck`,
`gosec`, and a short fuzz pass over the DNS-response parser
(`daemon/dns/fuzz_test.go`). Run this on every rebase onto upstream.

## Deploy checklist

1. **Provision mTLS certs** (via your config management) to
   `/etc/opensnitchd/certs/` on the workstation:
   `ca-cert.pem`, `server-cert.pem`, `client-cert.pem`, `client-key.pem`
   (root-owned; key `0400`). The GUI presents the server cert/key; the daemon
   presents the client cert. `ClientAuthType` is `req-and-verify-cert`.
2. **Set your UID** in `default-config.json`'s `Server.Address` (`id -u`).
3. Ensure the GUI creates `/run/user/<uid>/opensnitch/` before binding (the
   GUI `chmod`s the socket to `0640`); add a user `tmpfiles.d` rule or an
   autostart `mkdir -p` if it doesn't exist yet.
4. Vendor dependencies for reproducible, offline builds:
   `cd daemon && go mod vendor` and build with `-mod=vendor`. Bump the stale
   `grpc`/`protobuf` deps and confirm `govulncheck` is clean.
5. Sign the built artifact (cosign) and verify the signature at deploy time.

## Open items to consider

- `DefaultAction: "allow"` means unmatched connections are allowed when the
  GUI is disconnected. For a stricter posture consider `deny`, accepting that
  you'll lose connectivity for unprompted apps when the GUI isn't running.
- The IOC-scanner task runner executes arbitrary `bin`/`args` as root from the
  tasks config (`daemon/tasks/iocscanner/.../executer.go`). Audit whether tasks
  can be set over the UI channel before enabling that feature.
