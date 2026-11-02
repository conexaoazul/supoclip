"""Offline QA-only audio-activity classification on a verified local MP4 fd.

Detecting an AAC stream is NOT proof that audio or human speech is audible.
This helper probes at most one small *sample* window and never produces
transcripts, derivatives, sound files, URLs or authorization decisions.

Execution security is NOT established by this Python function. Use a
non-networked, low-privilege resource-capped media sandbox in real QA.
No live SupoClip adapter, worker dispatch, Odoo or n8n connection.
"""

import math
import os
import re
import stat
import subprocess

from .media_evidence import EvidenceDenied, ffprobe_fd

_PEAK_RE = re.compile(r"\bmax_volume:\s*(-inf|[-+]?[0-9]+(?:\.[0-9]+)?)\s*dB\b")
MAX_WINDOW_SECONDS = 15
# QA discrimination threshold, NOT a broadcast loudness or VAD standard.
SILENCE_PEAK_THRESHOLD_DBFS = -55.0


class AudioWindowDenied(ValueError):
    """Safe, redacted reason for an unverified audio QA measurement."""


def _peak_dbfs(stderr):
    if not isinstance(stderr, bytes) or not 0 < len(stderr) <= 32768:
        raise AudioWindowDenied("invalid_audio_measurement")
    try:
        lines = stderr.decode("utf-8", errors="replace").splitlines()
        hits = [_PEAK_RE.search(line) for line in lines]
        hits = [match.group(1) for match in hits if match]
        if len(hits) != 1:
            raise AudioWindowDenied("ambiguous_audio_peak")
        peak = -math.inf if hits[0] == "-inf" else float(hits[0])
        if math.isnan(peak) or peak > 0 or (math.isfinite(peak) and peak < -150):
            raise AudioWindowDenied("invalid_audio_peak")
        return peak
    except (OverflowError, ValueError) as exc:
        if isinstance(exc, AudioWindowDenied):
            raise
        raise AudioWindowDenied("invalid_audio_measurement") from exc


def sample_audio_fd(fd, *, seconds=8, probe_fn=None):
    """Inspect fixed first N seconds; never assert whole-source silence.

    `fd` must have been opened by the trusted tenant-scoped path resolver.
    MP4 metadata and source authorization are independent prereqs. The
    returned classification is only a technical QA observation.
    """
    if (type(fd) is not int or fd < 0 or type(seconds) is not int
            or not 1 <= seconds <= MAX_WINDOW_SECONDS):
        raise AudioWindowDenied("invalid_audio_context")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 12 <= info.st_size <= 1_000_000_000:
            raise AudioWindowDenied("invalid_audio_file")
    except OSError as exc:
        raise AudioWindowDenied("invalid_audio_descriptor") from exc
    if probe_fn is None:
        probe_fn = ffprobe_fd
    if not callable(probe_fn):
        raise AudioWindowDenied("audio_probe_unconfigured")
    try:
        probe = probe_fn(fd)
    except (EvidenceDenied, OSError, ValueError) as exc:
        raise AudioWindowDenied("audio_stream_probe_failed") from exc
    streams = probe.get("streams") if isinstance(probe, dict) else None
    if (not isinstance(streams, list) or not 1 <= len(streams) <= 16
            or any(not isinstance(s, dict) for s in streams)):
        raise AudioWindowDenied("audio_stream_metadata_invalid")
    audio = [s for s in streams if s.get("codec_type") == "audio"]
    if len(audio) > 1:
        raise AudioWindowDenied("multiple_audio_tracks_unreviewed")
    if not audio:
        return {
            "classification": "NO_AUDIO_STREAM",
            "audio_stream_present": False,
            "speech_verified": False,
            "window_seconds_requested": 0,
            "peak_dbfs": None,
            "execution": "DISABLED",
        }
    if audio[0].get("codec_name") not in {"aac", "mp3", "opus"}:
        raise AudioWindowDenied("unsupported_audio_codec")

    args = [
        "ffmpeg", "-hide_banner", "-nostdin", "-v", "info",
        "-protocol_whitelist", "file",
        "-i", "/proc/self/fd/" + str(fd),
        "-map", "0:a:0", "-vn", "-sn", "-dn", "-t", str(seconds),
        "-af", "volumedetect", "-f", "null", "-",
    ]
    before = os.fstat(fd)
    try:
        proc = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=25, check=False,
            pass_fds=(fd,),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AudioWindowDenied("audio_meter_unavailable") from exc
    after = os.fstat(fd)
    if (before.st_ino != after.st_ino or before.st_dev != after.st_dev
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns):
        raise AudioWindowDenied("media_changed_during_audio_probe")
    if proc.returncode != 0:
        raise AudioWindowDenied("audio_meter_failed")
    peak = _peak_dbfs(proc.stderr)
    silent = peak <= SILENCE_PEAK_THRESHOLD_DBFS
    return {
        "classification": (
            "SAMPLED_AUDIO_SILENT" if silent
            else "SAMPLED_AUDIO_ACTIVITY_UNVERIFIED"
        ),
        "audio_stream_present": True,
        # Speech detection requires a separate validated VAD/transcription
        # and rights gate. A sound or music is NOT a human voice.
        "speech_verified": False,
        "window_seconds_requested": seconds,
        "peak_dbfs": peak if math.isfinite(peak) else None,
        "execution": "DISABLED",
    }
