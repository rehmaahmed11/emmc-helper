"""Local web UI server (standard library only).

Why a web UI instead of Qt: a repair shop machine may have any Python, on any OS, often with
locked-down permissions. A browser needs nothing installed, looks identical everywhere, and
the same API is scriptable.

Security model: the server is meant for localhost use, but to be usable from another machine on
the bench it can bind a LAN address. Therefore every API call needs the session token that is
printed at startup (and embedded in the URL you open). Long operations run as jobs so the UI can
show progress and remain responsive.

    revive serve                 # http://127.0.0.1:8765
    revive serve --demo --open   # with the simulator, and open a browser
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import socket
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .. import util
from . import api

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_PORT = 8765

# Operations that can take minutes: run them as jobs instead of blocking the request.
JOB_ROUTES = {"dump.extract", "demo.build", "manifest.create", "convert"}


@dataclass
class Job:
    id: str
    route: str
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "queued"          # queued | running | done | failed
    progress: float = 0.0
    message: str = ""
    log: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: str = ""
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "route": self.route, "status": self.status,
            "progress": round(self.progress, 3), "message": self.message,
            "log": self.log[-60:], "result": self.result, "error": self.error,
            "started": self.started, "finished": self.finished,
            "elapsed": round((self.finished or time.time()) - self.started, 2),
        }


class JobManager:
    def __init__(self, ctx: Dict[str, Any]):
        self.ctx = ctx
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()

    def submit(self, route: str, payload: Dict[str, Any]) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], route=route, payload=payload)
        with self.lock:
            self.jobs[job.id] = job
        thread = threading.Thread(target=self._run, args=(job,), daemon=True,
                                  name=f"revive-job-{route}")
        thread.start()
        return job

    def _run(self, job: Job) -> None:
        job.status = "running"

        def progress(done: int, total: int, label: str = "") -> None:
            job.progress = (done / total) if total else 0.0
            job.message = f"{label} {util.human_size(done)}" + (
                f" / {util.human_size(total)}" if total else "")
            if len(job.log) < 400:
                job.log.append(job.message)

        self.ctx["progress"] = progress
        try:
            result = api.dispatch(job.route, job.payload, self.ctx)
            job.result = result
            job.status = "done" if result.get("ok", True) else "failed"
            if not result.get("ok", True):
                job.error = str(result.get("error", "operation failed"))
        except Exception as exc:  # pragma: no cover - defensive
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.log.append(traceback.format_exc(limit=3))
        finally:
            job.progress = 1.0 if job.status == "done" else job.progress
            job.finished = time.time()

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def list(self) -> List[Dict[str, Any]]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j.started, reverse=True)
            return [j.to_dict() for j in jobs[:30]]


class ReviveHandler(BaseHTTPRequestHandler):
    server_version = f"Revive/{util.__version__}"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - base class API
        if self.server.verbose:  # type: ignore[attr-defined]
            sys.stderr.write(f"[http] {self.address_string()} {fmt % args}\n")

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, inject_token: bool = False) -> None:
        if not path.exists() or not path.is_file():
            self._send_json({"ok": False, "error": "not found"}, 404)
            return
        body = path.read_bytes()
        if inject_token and path.suffix.lower() == ".html":
            # Hand the page its own session token when the request came from this machine.
            # A browser that opens the printed URL already has the token in the query string;
            # this covers the case where a local tool (or a preview proxy on the same host)
            # opens the plain address. Requests from other machines never get the injection.
            token = str(getattr(self.server, "token", "") or "")
            if token:
                banner = (f'<script>window.REVIVE_TOKEN={json.dumps(token)};</script>'
                          .encode("utf-8"))
                marker = b"<head>"
                body = (body.replace(marker, marker + banner, 1) if marker in body
                        else banner + body)
        mime, _ = mimetypes.guess_type(str(path))
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _is_loopback(self) -> bool:
        """True when the request came from this machine (127.0.0.1/::1, IPv4-mapped included)."""
        host = (self.client_address[0] or "") if self.client_address else ""
        return host in ("127.0.0.1", "::1", "localhost") or host.startswith("127.") or \
            host.startswith("::ffff:127.")

    def _authorised(self, query: Dict[str, List[str]]) -> bool:
        token = self.server.token          # type: ignore[attr-defined]
        if not token:
            return True
        supplied = self.headers.get("X-Revive-Token") or ""
        if not supplied and "token" in query:
            supplied = query["token"][0]
        return secrets.compare_digest(supplied, token)

    # -- routes -----------------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - base class API
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path

        if route in ("/", "/index.html"):
            self._send_file(STATIC_DIR / "index.html", inject_token=self._is_loopback())
            return
        if route == "/healthz":
            self._send_json({"ok": True, "version": util.__version__,
                             "demo": self.server.ctx.get("demo", False)})  # type: ignore[attr-defined]
            return
        if route == "/api/jobs":
            if not self._authorised(query):
                self._send_json({"ok": False, "error": "unauthorised"}, 401)
                return
            self._send_json({"ok": True, "jobs": self.server.jobs.list()})  # type: ignore[attr-defined]
            return
        if route == "/api/job":
            if not self._authorised(query):
                self._send_json({"ok": False, "error": "unauthorised"}, 401)
                return
            job = self.server.jobs.get(query.get("id", [""])[0])  # type: ignore[attr-defined]
            if job is None:
                self._send_json({"ok": False, "error": "unknown job"}, 404)
                return
            self._send_json({"ok": True, "job": job.to_dict()})
            return
        if route.startswith("/static/"):
            rel = unquote(route[len("/static/"):])
            target = (STATIC_DIR / rel).resolve()
            if STATIC_DIR.resolve() in target.parents or target.parent == STATIC_DIR.resolve():
                self._send_file(target)
            else:
                self._send_json({"ok": False, "error": "invalid path"}, 400)
            return

        self._send_json({"ok": False, "error": "unknown route", "path": route}, 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._authorised(query):
            self._send_json({"ok": False, "error": "unauthorised",
                             "hint": "open the URL printed by `revive serve` (it contains the token)"}, 401)
            return

        payload = self._read_body()
        route = parsed.path
        if route == "/api/call":
            name = str(payload.get("route", ""))
            args = payload.get("payload") or {}
            ctx = dict(self.server.ctx)          # type: ignore[attr-defined]
            ctx["started"] = time.time()
            if name in JOB_ROUTES and not payload.get("sync"):
                job = self.server.jobs.submit(name, args)      # type: ignore[attr-defined]
                self._send_json({"ok": True, "job": job.to_dict()})
                return
            self._send_json(api.dispatch(name, args, ctx))
            return
        if route == "/api/shutdown":
            self._send_json({"ok": True, "message": "shutting down"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self._send_json({"ok": False, "error": "unknown route", "path": route}, 404)


class ReviveServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, ctx: Dict[str, Any], token: str, verbose: bool):
        super().__init__(address, handler)
        self.ctx = ctx
        self.token = token
        self.verbose = verbose
        self.jobs = JobManager(ctx)


def lan_address() -> str:
    """Best-guess LAN address, for printing a URL that works from another machine."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("10.255.255.255", 1))
        address = sock.getsockname()[0]
        sock.close()
        return address
    except Exception:
        return "127.0.0.1"


def serve(host: str = "0.0.0.0", port: int = DEFAULT_PORT, demo: bool = False,
          open_browser: bool = False, verbose: bool = False,
          storage: Optional[Path] = None, token: Optional[str] = None) -> int:
    import tempfile

    ctx: Dict[str, Any] = {
        "demo": demo,
        "demo_storage": Path(storage) if storage
        else Path(tempfile.gettempdir()) / "revive-mock-emmc.bin",
        "started": time.time(),
    }

    session_token = token if token is not None else secrets.token_urlsafe(16)
    try:
        server = ReviveServer((host, port), ReviveHandler, ctx, session_token, verbose)
    except OSError as exc:
        print(f"Could not start the server on {host}:{port}: {exc}", file=sys.stderr)
        print("Another instance may be running, or the port is in use. Try --port 8899.",
              file=sys.stderr)
        return 1

    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{display_host}:{actual_port}/?token={session_token}"

    print(f"\n{util.TOOL_NAME} {util.__version__} - web UI")
    print("-" * 62)
    print(f"  {url}")
    if host in ("0.0.0.0", "::"):
        print(f"  from another machine on the bench: http://{lan_address()}:{actual_port}/"
              f"?token={session_token}")
    print(f"  token: {session_token}")
    if demo:
        print("  DEMO MODE: a simulated device, nothing touches real hardware.")
    if not util.__dict__.get("_usbmodes_checked"):
        from ..core import usbmodes

        if not usbmodes.libusb_available():
            print(f"  note: USB support is off until you run: {usbmodes.install_hint()}")
            print("        (everything that works on files still works right now)")
    print("  press Ctrl+C to stop\n")

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        server.server_close()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="revive serve", description="Run the Revive web UI")
    parser.add_argument("--host", default="0.0.0.0",
                        help="bind address (default 0.0.0.0; use 127.0.0.1 for this machine only)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--demo", action="store_true", help="use the simulated device")
    parser.add_argument("--open", action="store_true", help="open a browser window")
    parser.add_argument("--verbose", action="store_true", help="log every HTTP request")
    parser.add_argument("--storage", type=Path, default=None,
                        help="file to back the simulated device with")
    parser.add_argument("--token", default=None, help="use a fixed session token (testing)")
    args = parser.parse_args(argv)
    return serve(args.host, args.port, args.demo, args.open, args.verbose, args.storage, args.token)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
