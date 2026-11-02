"""QA-only local upload evidence gate, with no HTTP, storage or worker wiring.

This is independent of user-supplied duration/rights booleans. A trusted,
server-side rights ledger must provide RightsApproval; mere construction of a
Python dataclass by a caller is NOT a legal attestation. This code must not
be imported as a live SupoClip media processor without explicit QA GO.

Upload refs are resolved only inside a per-tenant private flat directory:
    <TRUSTED_QA_ROOT>/<verified_tenant>/<opaque_upload_id>.mp4
No arbitrary path or URL is accepted.
"""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import re
import stat
import subprocess
from typing import Callable


MAX_SOURCE_BYTES = 1_000_000_000  # 1 GB decimal, conservative QA limit
MAX_SOURCE_SECONDS = 1800
MAX_WIDTH = 3840
MAX_HEIGHT = 2160
UPLOAD_ID_RE = re.compile(r"^upload:([A-Za-z0-9][A-Za-z0-9._-]{7,127})$")
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,79}$")
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{4,159}$")
APPROVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")


class EvidenceDenied(ValueError):
    """Safe validation error with no filesystem path or media contents."""


@dataclass(frozen=True)
class RightsApproval:
    """Must originate from a separately authenticated approval repository."""

    tenant_id: str
    source_ref: str
    source_sha256: str
    rights_ref: str
    approved_by: str
    approved_at: int
    valid_until: int
    processing_allowed: bool

    def matches(self, *, tenant_id, source_ref, digest, now):
        return (
            self.tenant_id == tenant_id
            and self.source_ref == source_ref
            and isinstance(self.source_sha256, str)
            and HASH_RE.fullmatch(self.source_sha256) is not None
            and self.source_sha256 == digest
            and isinstance(self.rights_ref, str)
            and REF_RE.fullmatch(self.rights_ref) is not None
            and isinstance(self.approved_by, str)
            and APPROVER_RE.fullmatch(self.approved_by) is not None
            and type(self.approved_at) is int
            and type(self.valid_until) is int
            and self.approved_at <= now <= self.valid_until
            and self.processing_allowed is True
        )


def ffprobe_fd(fd):
    """Explicit opt-in ffprobe on a previously opened *regular* QA file.

    Linux-only /proc fd path keeps this input bound to the verified descriptor.
    The ffprobe binary, sandbox and system packages must be reviewed/pinned by
    infrastructure; this module does not install or run a server.
    """
    if not isinstance(fd, int) or fd < 0:
        raise EvidenceDenied("invalid_media_descriptor")
    path = "/proc/self/fd/" + str(fd)
    args = [
        "ffprobe", "-v", "error", "-protocol_whitelist", "file", "-probesize", "1048576",
        "-analyzeduration", "3000000",
        "-show_entries",
        "format=duration,size,format_name:stream=codec_type,codec_name,width,height",
        "-of", "json", "-i", path,
    ]
    try:
        proc = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20, check=False,
            pass_fds=(fd,),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceDenied("media_probe_unavailable") from exc
    if proc.returncode != 0 or not 0 < len(proc.stdout) <= 32768:
        raise EvidenceDenied("media_probe_failed")
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise EvidenceDenied("invalid_probe_response") from exc


def _inspect_probe(probe, claimed_seconds):
    if not isinstance(probe, dict) or not isinstance(probe.get("format"), dict):
        raise EvidenceDenied("invalid_probe_response")
    record = probe["format"]
    names = record.get("format_name")
    if not isinstance(names, str) or "mp4" not in names.split(","):
        raise EvidenceDenied("unsupported_container")
    try:
        duration = Decimal(str(record["duration"]))
    except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
        raise EvidenceDenied("invalid_duration") from exc
    if not duration.is_finite() or not 0 < duration <= MAX_SOURCE_SECONDS:
        raise EvidenceDenied("invalid_duration")
    if type(claimed_seconds) is not int or not 1 <= claimed_seconds <= MAX_SOURCE_SECONDS:
        raise EvidenceDenied("invalid_duration_claim")
    if abs(duration - Decimal(claimed_seconds)) > Decimal("2"):
        raise EvidenceDenied("duration_mismatch")
    streams = probe.get("streams")
    if not isinstance(streams, list) or len(streams) > 16:
        raise EvidenceDenied("invalid_streams")
    videos = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"]
    if len(videos) != 1:
        raise EvidenceDenied("invalid_video_stream_count")
    video = videos[0]
    if video.get("codec_name") not in {"h264", "hevc"}:
        raise EvidenceDenied("unsupported_codec")
    width, height = video.get("width"), video.get("height")
    if (type(width) is not int or type(height) is not int
            or not 1 <= width <= MAX_WIDTH or not 1 <= height <= MAX_HEIGHT):
        raise EvidenceDenied("invalid_dimensions")
    # Only normal audio/video streams permitted. Avoid unexpected embedded data,
    # subtitle attachments and opaque sidecar streams in the minimal QA pilot.
    if any(not isinstance(s, dict) or s.get("codec_type") not in {"audio", "video"}
           for s in streams):
        raise EvidenceDenied("unexpected_stream")
    return duration, width, height, video["codec_name"]


def _file_changed(before, after):
    """Detect in-place edits as well as size or inode changes while probing."""
    return (
        before.st_size != after.st_size
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    )


def attest_private_upload(*, qa_root, verified_tenant, upload_ref,
                          claimed_duration_seconds, rights_record,
                          now, probe_fn: Callable = None):
    """Read+hash isolated media and compare to an independently approved record.

    The identity parameter MUST be derived from authenticated gateway key
    mapping, and rights_record MUST come from a restricted, verified
    server-side approval store. Never source either from the request JSON.
    Tests may inject a synthetic probe; such tests do not constitute real
    ffprobe or legal/rights proof.
    """
    if probe_fn is None or not callable(probe_fn):
        raise EvidenceDenied("media_probe_not_configured")
    if (not isinstance(verified_tenant, str) or
            TENANT_RE.fullmatch(verified_tenant) is None):
        raise EvidenceDenied("invalid_verified_tenant")
    match = UPLOAD_ID_RE.fullmatch(upload_ref) if isinstance(upload_ref, str) else None
    if match is None:
        raise EvidenceDenied("upload_reference_required")
    if not isinstance(rights_record, RightsApproval) or type(now) is not int:
        raise EvidenceDenied("trusted_approval_required")
    if not isinstance(qa_root, (str, bytes, os.PathLike)):
        raise EvidenceDenied("invalid_qa_root")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    dirflags = flags | os.O_DIRECTORY
    rootfd = tenantfd = mediafd = None
    try:
        rootfd = os.open(qa_root, dirflags)
        tenantfd = os.open(verified_tenant, dirflags, dir_fd=rootfd)
        mediafd = os.open(match.group(1) + ".mp4", flags, dir_fd=tenantfd)
        file_info = os.fstat(mediafd)
        if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                or not 12 <= file_info.st_size <= MAX_SOURCE_BYTES):
            raise EvidenceDenied("invalid_media_file")
        if os.read(mediafd, 12)[4:8] != b"ftyp":
            raise EvidenceDenied("unsupported_container")
        os.lseek(mediafd, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        size_read = 0
        while True:
            block = os.read(mediafd, 1024 * 1024)
            if not block:
                break
            size_read += len(block)
            if size_read > MAX_SOURCE_BYTES:
                raise EvidenceDenied("media_size_exceeded")
            hasher.update(block)
        if (size_read != file_info.st_size or
                _file_changed(file_info, os.fstat(mediafd))):
            raise EvidenceDenied("media_changed_during_read")
        digest = hasher.hexdigest()
        if not rights_record.matches(
                tenant_id=verified_tenant, source_ref=upload_ref,
                digest=digest, now=now):
            raise EvidenceDenied("rights_approval_missing_or_mismatched")
        os.lseek(mediafd, 0, os.SEEK_SET)
        probe = probe_fn(mediafd)
        duration, width, height, codec = _inspect_probe(
            probe, claimed_duration_seconds)
        if _file_changed(file_info, os.fstat(mediafd)):
            raise EvidenceDenied("media_changed_during_probe")
        return {
            "tenant_id": verified_tenant,
            "source_ref": upload_ref,
            "source_sha256": digest,
            "size_bytes": size_read,
            "duration_seconds": float(duration),
            "width": width,
            "height": height,
            "codec": codec,
            "rights_ref": rights_record.rights_ref,
            "approved_by": rights_record.approved_by,
            "execution": "DISABLED",
            "evidence": "QA_LOCAL_ATTESTATION_ONLY",
        }
    except (OSError, ValueError) as exc:
        if isinstance(exc, EvidenceDenied):
            raise
        raise EvidenceDenied("media_unavailable") from exc
    finally:
        for fd in (mediafd, tenantfd, rootfd):
            if fd is not None:
                os.close(fd)
