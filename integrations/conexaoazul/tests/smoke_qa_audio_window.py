#!/usr/bin/env python3
"""Manual synthetic QA media: no track, silent AAC, and audible generated tone.

Creates only original 1-second files in an auto-deleted temp directory.
Uses host ffprobe/ffmpeg; does NOT prove actual speech, sandbox isolation,
customer media rights, production storage ACL or worker runtime readiness.
No network, cloud, upload, transcription, Odoo or social publishing.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.qa_audio_window import sample_audio_fd


def create_mp4(path, kind):
    args = [
        "ffmpeg", "-hide_banner", "-nostdin", "-v", "error", "-y",
        "-f", "lavfi", "-i", "color=c=blue:s=128x128:r=10",
    ]
    if kind == "silence":
        args += ["-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo"]
    elif kind == "tone":
        args += ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000"]
    args += ["-t", "1", "-c:v", "libx264", "-preset", "ultrafast",
             "-pix_fmt", "yuv420p"]
    if kind == "no_track":
        args += ["-an"]
    else:
        args += ["-c:a", "aac", "-b:a", "64k"]
    args += ["-movflags", "+faststart", str(path)]
    result = subprocess.run(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode != 0 or not path.is_file():
        raise RuntimeError("synthetic_media_generation_failed")


def main():
    expected = {
        "no_track": "NO_AUDIO_STREAM",
        "silence": "SAMPLED_AUDIO_SILENT",
        "tone": "SAMPLED_AUDIO_ACTIVITY_UNVERIFIED",
    }
    checks = {}
    with tempfile.TemporaryDirectory(prefix="blue-video-audio-qa-") as dir:
        for kind, wanted in expected.items():
            path = pathlib.Path(dir) / (kind + ".mp4")
            create_mp4(path, kind)
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                actual = sample_audio_fd(fd, seconds=1)
            finally:
                os.close(fd)
            if actual["classification"] != wanted:
                raise AssertionError("classification_failed_" + kind)
            if actual["speech_verified"] is not False:
                raise AssertionError("speech_must_remain_unverified")
            if actual["execution"] != "DISABLED":
                raise AssertionError("unexpected_execution")
            checks[kind] = {
                "classification": actual["classification"],
                "peak_dbfs": actual["peak_dbfs"],
                "audio_stream_present": actual["audio_stream_present"],
            }
    print(json.dumps({
        "result": "PASS_SYNTHETIC_AUDIO_QA",
        "checks": checks,
        "real_ffmpeg": True,
        "real_ffprobe": True,
        "speech_verified": False,
        "rights": "ORIGINAL_SYNTHETIC_FIXTURE_ONLY",
        "external_data": False,
        "production_deploy": False,
        "publishing": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
