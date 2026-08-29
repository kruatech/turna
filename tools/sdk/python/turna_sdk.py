"""Python client for the turna management API.

Why Python and not Rust: the callers are operators and their automation, and a
Rust SDK would need them to build it. A Rust caller already has the proto and
tonic.

Install::

    pip install grpcio grpcio-tools
    python -m grpc_tools.protoc -I crates/control/proto \\
        --python_out=. --grpc_python_out=. crates/control/proto/management.proto

Then::

    from turna_sdk import Turna

    with Turna("node1.internal:9443", ca="ca.pem",
               cert="client.pem", key="client-key.pem") as t:
        print(t.stats().active_allocations)
        t.drain(reason="rolling upgrade")

mTLS is not optional in the constructor. The management plane requires it, and an
SDK that made it a keyword argument with a default would invite an insecure call
that works on a laptop and fails in production — or worse, works in production
because somebody turned mTLS off to make the SDK work.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Iterator, Optional

try:
    import grpc
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "grpcio is required: pip install grpcio grpcio-tools"
    ) from e

try:
    import management_pb2 as pb
    import management_pb2_grpc as pb_grpc
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "The generated stubs are missing. Run:\n"
        "  python -m grpc_tools.protoc -I crates/control/proto \\\n"
        "      --python_out=. --grpc_python_out=. \\\n"
        "      crates/control/proto/management.proto"
    ) from e


class TurnaError(Exception):
    """A management call failed."""


class PermissionDenied(TurnaError):
    """The client certificate's role does not grant this operation.

    Separate from the generic error because it is the one an operator can fix
    themselves — by asking for a role binding — and the server deliberately does
    not say which permission was needed. That detail is in the node's audit log.
    """


class VersionConflict(TurnaError):
    """Someone else changed the configuration since it was read.

    Raised for the optimistic-concurrency mismatch. Not retried automatically:
    the correct response is to re-read, decide whether the change still makes
    sense against the new state, and submit again. A blind retry would apply an
    edit computed against configuration that no longer exists.
    """


@dataclass
class Stats:
    active_allocations: int
    total_allocations: int
    packets_received: int
    packets_sent: int
    bytes_received: int
    bytes_sent: int
    auth_failures: int
    rate_limited: int
    send_queue_dropped: int

    @property
    def dropping(self) -> bool:
        """True when the node has discarded media before sending it.

        Worth surfacing as a property because it is the signal a client-side
        loss measurement cannot see, and reading it as zero when it is not is how
        a capacity figure comes out 27 % too high.
        """
        return self.send_queue_dropped > 0


class Turna:
    """A connection to one node's management API."""

    def __init__(
        self,
        target: str,
        *,
        ca: str,
        cert: str,
        key: str,
        timeout: float = 10.0,
        correlation_id: Optional[str] = None,
    ):
        """
        :param target: ``host:port``
        :param ca: PEM bundle that signs the server certificate
        :param cert: client certificate, PEM
        :param key: client private key, PEM
        :param correlation_id: attached to every call and echoed into the node's
            logs and audit entries. Defaults to a fresh UUID per client, which is
            more useful than none: a support conversation can start from "find
            this string" rather than from a timestamp and a hope.
        """
        with open(ca, "rb") as f:
            ca_bytes = f.read()
        with open(cert, "rb") as f:
            cert_bytes = f.read()
        with open(key, "rb") as f:
            key_bytes = f.read()

        creds = grpc.ssl_channel_credentials(
            root_certificates=ca_bytes,
            private_key=key_bytes,
            certificate_chain=cert_bytes,
        )
        self._channel = grpc.secure_channel(target, creds)
        self._stub = pb_grpc.TurnaManagementStub(self._channel)
        self._timeout = timeout
        self._correlation = correlation_id or str(uuid.uuid4())
        self._target = target

    # ── plumbing ────────────────────────────────────────────────────────────

    def _md(self) -> list[tuple[str, str]]:
        return [("x-turna-correlation-id", self._correlation)]

    def _call(self, method, request):
        try:
            return method(request, timeout=self._timeout, metadata=self._md())
        except grpc.RpcError as e:
            code = e.code()
            if code == grpc.StatusCode.PERMISSION_DENIED:
                raise PermissionDenied(
                    f"{self._target}: {e.details()}. The node does not say which "
                    f"permission was missing — that is in its audit log, under "
                    f"correlation id {self._correlation}."
                ) from e
            if code == grpc.StatusCode.ABORTED:
                raise VersionConflict(f"{self._target}: {e.details()}") from e
            raise TurnaError(f"{self._target}: {code.name}: {e.details()}") from e

    @staticmethod
    def _idem() -> str:
        """A fresh idempotency key.

        Generated per call rather than per client: the key exists so a retry of a
        *lost response* does not apply the operation twice, which means it must
        identify the operation and not the caller.
        """
        return str(uuid.uuid4())

    # ── reading ─────────────────────────────────────────────────────────────

    def stats(self) -> Stats:
        r = self._call(self._stub.GetServerStats, pb.GetServerStatsRequest())
        return Stats(
            active_allocations=r.active_allocations,
            total_allocations=r.total_allocations,
            packets_received=r.packets_received,
            packets_sent=r.packets_sent,
            bytes_received=r.bytes_received,
            bytes_sent=r.bytes_sent,
            auth_failures=r.auth_failures,
            rate_limited=r.rate_limited,
            send_queue_dropped=getattr(r, "send_queue_dropped", 0),
        )

    def allocations(self, *, limit: int = 100) -> list:
        r = self._call(
            self._stub.ListAllocations, pb.ListAllocationsRequest(limit=limit)
        )
        return list(r.allocations)

    def config(self):
        return self._call(self._stub.GetConfig, pb.GetConfigRequest())

    def watch_allocations(self) -> Iterator:
        """Stream allocation events until the caller stops consuming.

        A generator, so a `break` closes the stream. The node counts open streams
        and force-closes them on shutdown, so a consumer that stops reading
        without breaking holds a slot until then.
        """
        stream = self._stub.WatchAllocations(
            pb.WatchAllocationsRequest(), metadata=self._md()
        )
        try:
            yield from stream
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                return
            raise TurnaError(f"{self._target}: watch failed: {e.details()}") from e

    # ── changing ────────────────────────────────────────────────────────────

    def drain(self, *, reason: str = "") -> None:
        """Stop accepting new allocations; let existing ones finish.

        Returns as soon as the node accepts the instruction, not when draining
        completes. Use :meth:`wait_drained` for that — a rolling upgrade that
        proceeds on the acknowledgement rather than on the outcome is how two
        nodes end up draining at once.
        """
        self._call(
            self._stub.SetDraining,
            pb.SetDrainingRequest(
                draining=True, reason=reason, idempotency_key=self._idem()
            ),
        )

    def undrain(self) -> None:
        self._call(
            self._stub.SetDraining,
            pb.SetDrainingRequest(draining=False, idempotency_key=self._idem()),
        )

    def wait_drained(self, *, timeout: float = 60.0, poll: float = 2.0) -> bool:
        """Block until no allocations remain, or the timeout expires.

        Returns True if it emptied. False means allocations are still held — and
        on a node whose clients vanished without a Refresh, that is the expected
        answer, because those allocations will not end until their lifetime does.
        The node's own drain has a bounded wait for the same reason.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.stats().active_allocations == 0:
                return True
            time.sleep(poll)
        return False

    def delete_allocation(self, allocation_id: str, *, reason: str = "") -> None:
        self._call(
            self._stub.DeleteAllocation,
            pb.DeleteAllocationRequest(
                allocation_id=allocation_id,
                reason=reason,
                idempotency_key=self._idem(),
            ),
        )

    def set_user_limits(self, username: str, **limits) -> None:
        self._call(
            self._stub.SetUserLimits,
            pb.SetUserLimitsRequest(
                username=username, idempotency_key=self._idem(), **limits
            ),
        )

    def update_config(self, *, expected_version: int, **changes) -> None:
        """Apply a configuration change, guarded by the version read earlier.

        ``expected_version`` is required rather than optional. Without it the call
        is a blind write, and the reason the field exists is that two operators
        editing during an incident is the normal case, not the exceptional one.
        """
        self._call(
            self._stub.UpdateConfig,
            pb.UpdateConfigRequest(
                expected_version=expected_version,
                idempotency_key=self._idem(),
                **changes,
            ),
        )

    # ── lifecycle ───────────────────────────────────────────────────────────

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "Turna":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def rolling_drain(nodes: list[Turna], *, timeout: float = 120.0):
    """Drain nodes one at a time, waiting for each before starting the next.

    Sequential on purpose. Draining a whole cluster at once moves every session
    simultaneously to whatever is left, which is the traffic spike a rolling
    upgrade exists to avoid.

    Yields ``(node, emptied)`` per node. A False does not stop the walk: an
    operator draining ten nodes wants to know which did not empty, not to have
    the procedure abandoned at the third.
    """
    for node in nodes:
        node.drain(reason="rolling upgrade")
        yield node, node.wait_drained(timeout=timeout)
