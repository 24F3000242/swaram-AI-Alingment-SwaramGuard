"""Egress proxy: enforcement that doesn't depend on the agent platform cooperating (Security Response).

The ingest gate only works if a platform asks it before acting, and a hijacked agent won't. Data theft has to leave
over the network, so the network path is where enforcement can't be skipped: whoever deploys the agents points their
outbound traffic at this proxy (HTTP_PROXY / HTTPS_PROXY), and every request is checked here.

    HTTPS_PROXY=http://<run_id>%2F<agent_id>:<agent api key>@guard-host:8899

For every outbound request the proxy:
- identifies the agent (proxy credentials `run_id/agent_id`, and its API key when SWARMGUARD_API_KEYS is on);
- refuses it (HTTP 403) if the destination isn't on the egress allowlist, or if the live guard has paused the agent or
  held its outbound transfers, or if the hijack tripwire fires; the refusal is logged as a blocked transfer;
- otherwise forwards it (plain HTTP, or an HTTPS CONNECT tunnel: the proxy sees the host, never the encrypted data)
  and logs an egress sensor record, so an upload the agent never reported shows up as a gateway bypass (SG-021).

Settings: SWARMGUARD_EGRESS_PROXY_PORT (start it with the app), SWARMGUARD_EGRESS_ALLOW (comma-separated hosts),
SWARMGUARD_EGRESS_MODE (`enforce` default, or `monitor`: log and flag but don't refuse). Optionally
a platform may name what it is sending in an `X-SwarmGuard-Resource` header (recorded, never forwarded), and for
demos and tests SWARMGUARD_EGRESS_RESOLVE (`host=ip:port,...`, `*` for any host): where to really connect for a destination name.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import threading
from urllib.parse import unquote, urlsplit

log = logging.getLogger(__name__)


def allow_hosts() -> set[str]:
    return {h.strip().lower() for h in os.getenv("SWARMGUARD_EGRESS_ALLOW", "").split(",") if h.strip()}


def resolve_map(raw: str | None = None) -> dict[str, tuple[str, int]]:
    """"approved-partner-api=127.0.0.1:9900,*=127.0.0.1:9900" -> {host: (ip, port)}."""
    raw = os.getenv("SWARMGUARD_EGRESS_RESOLVE", "") if raw is None else raw
    out = {}
    for part in raw.split(","):
        host, _, addr = part.strip().partition("=")
        ip, _, port = addr.rpartition(":")
        if host and ip and port.isdigit():
            out[host.lower()] = (ip, int(port))
    return out


def _identity(headers: dict[str, str]) -> tuple[str | None, str | None, str | None]:
    """(run_id, agent_id, key) from Proxy-Authorization: Basic base64("run_id/agent_id:key")."""
    raw = headers.get("proxy-authorization", "")
    if not raw.lower().startswith("basic "):
        return None, None, None
    try:
        user, _, key = base64.b64decode(raw[6:].strip()).decode().partition(":")
    except Exception:
        return None, None, None
    run_id, _, agent_id = unquote(user).partition("/")
    return (run_id or None), (agent_id or None), (key or None)


class EgressProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 8899, mode: str | None = None, allow: set[str] | None = None,
                 pipeline=None, resolve: dict[str, tuple[str, int]] | None = None):
        self.host, self.port, self.pipeline = host, port, pipeline  # pipeline: where proxy records are stored
        self.resolve = resolve if resolve is not None else resolve_map()
        self.mode = (mode or os.getenv("SWARMGUARD_EGRESS_MODE", "enforce")).lower()
        self.allow = allow if allow is not None else allow_hosts()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server = None
        self.decisions: list[dict] = []  # recent decisions (for tests and the UI)

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> "EgressProxy":
        ready = threading.Event()

        def run() -> None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(asyncio.start_server(self._handle, self.host, self.port))
            self.port = self.server.sockets[0].getsockname()[1]  # port 0 -> the one the OS picked
            ready.set()
            self.loop.run_forever()

        threading.Thread(target=run, name="swarmguard-egress-proxy", daemon=True).start()
        ready.wait(5)
        log.info("SwarmGuard egress proxy on %s:%s (%s)", self.host, self.port, self.mode)
        return self

    def stop(self) -> None:
        if self.loop and self.server:
            async def shutdown():
                self.server.close()
                await self.server.wait_closed()
            try:
                asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(2)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)

    # ---------------------------------------------------------------- decision
    def decide(self, run_id: str | None, agent_id: str | None, key: str | None, host: str, method: str,
               resource: str | None = None) -> tuple[int, str | None]:
        """(HTTP status to answer with, or 0 to forward; reason). Records the outcome in the agent's live session."""
        from app import auth
        from app.services import ingest

        if not agent_id:
            return 407, "proxy credentials must name the agent: run_id/agent_id"
        session = ingest.SESSIONS.get(run_id or "")
        if session is not None and session.require_identity:  # the agent's own token, not a shared key
            if not session.verify(agent_id, key):
                return 407, f"proxy password is not {agent_id}'s agent token"
        elif auth.enabled():
            who = auth.identify(key)
            if not auth.allowed(who, "agent"):
                return 407, "proxy credentials missing or not an agent key"
        dest = f"external:{host.lower()}"
        action = "download" if method == "GET" else "upload"
        reasons = []
        if host.lower() not in self.allow:
            reasons.append(f"destination {host} is not on the egress allowlist")
        guard_reason = session.gate({"agent_id": agent_id, "event_type": "data_transfer", "action": action,
                                     "target": dest, "resource": resource,
                                     # destinations are this proxy's allowlist's job (above): ask the guard only about
                                     # pauses, holds and the hijack tripwire
                                     "policy_check": False})["reason"] if session else None
        if guard_reason:
            reasons.append(guard_reason)
        refuse = bool(reasons) and (self.mode == "enforce" or guard_reason is not None)
        detail = "; ".join(reasons) or None
        self.decisions.append({"run_id": run_id, "agent_id": agent_id, "host": host, "method": method,
                               "allowed": not refuse, "reason": detail})
        del self.decisions[:-500]
        if session:
            if refuse:  # an attempt the network refused: a real block, logged as the agent's own (denied) action
                record = ({"agent_id": agent_id, "event_type": "data_transfer", "action": action, "target": dest,
                           **({"resource": resource} if resource else {}),
                           "status": "denied", "gateway_decision": "blocked",
                           "payload": {"source": "egress-proxy", "enforced_by": "egress proxy", "gateway_reason": detail}})
            else:  # it left: an independent sensor record (fused with what the agent reports)
                record = ({"agent_id": agent_id, "event_type": "observation", "action": action, "target": dest,
                           **({"resource": resource} if resource else {}),
                           "payload": {"source": "egress-proxy", "mirrors": "data_transfer",
                                       **({"flag": detail} if detail else {})}})
            if self.pipeline is not None:
                ingest.add_events(self.pipeline, run_id, [record])  # stored, so it counts when the session finishes
            else:
                session.add(record)
        return (403, detail) if refuse else (0, detail)

    # ---------------------------------------------------------------- protocol
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        except Exception:
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            writer.close()
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        run_id, agent_id, key = _identity(headers)
        if method.upper() == "CONNECT":
            host, _, port = target.rpartition(":")
            port = int(port or 443)
        else:
            u = urlsplit(target)
            host, port = u.hostname or "", u.port or 80
        try:
            status, reason = await asyncio.get_running_loop().run_in_executor(
                None, self.decide, run_id, agent_id, key, host, method.upper(),
                headers.get("x-swarmguard-resource"))  # optional: what a cooperating platform says it is sending
        except Exception as exc:  # fail closed: if we can't decide, nothing leaves
            log.exception("egress proxy decision failed")
            status, reason = 403, f"guard error ({type(exc).__name__}); refused"
        if status:
            text = {403: "Forbidden", 407: "Proxy Authentication Required"}[status]
            body = f"SwarmGuard egress proxy refused: {reason}\n".encode()
            extra = 'Proxy-Authenticate: Basic realm="swarmguard"\r\n' if status == 407 else ""
            writer.write(f"HTTP/1.1 {status} {text}\r\n{extra}Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + body)
            await writer.drain()
            writer.close()
            return
        try:
            real = self.resolve.get(host.lower()) or self.resolve.get("*") or (host, port)
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(*real), 10)
        except Exception as exc:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            log.info("egress proxy: cannot reach %s:%s (%s)", host, port, exc)
            return
        if method.upper() == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:  # absolute-form -> origin-form, without our proxy headers
            u = urlsplit(target)
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            ours = ("proxy-authorization", "proxy-connection", "x-swarmguard-")
            kept = [ln for ln in lines[1:] if ln and not ln.lower().startswith(ours)]
            up_w.write((f"{method} {path} {version}\r\n" + "\r\n".join(kept) + "\r\n\r\n").encode("latin-1"))
            await up_w.drain()
        await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer), return_exceptions=True)

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        finally:
            dst.close()


PROXY: EgressProxy | None = None


def start_from_env(pipeline=None) -> EgressProxy | None:
    global PROXY
    port = os.getenv("SWARMGUARD_EGRESS_PROXY_PORT")
    if not port:
        return None
    PROXY = EgressProxy(host=os.getenv("SWARMGUARD_EGRESS_PROXY_HOST", "127.0.0.1"), port=int(port),
                        pipeline=pipeline).start()
    return PROXY
