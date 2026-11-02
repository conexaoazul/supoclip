# QA Audio Window — nonexecuting media safety check

**Date:** 2026-11-02. **Branch:** SupoClip PR #1 (draft).
**Scope:** QA-only, original/synthetic/authorized private MP4. No runtime integration, dispatch, social publishing, rights grant, transcoding or tenant authority.

## Why

A real 81.4-second promotional/event recording in the user's connected Drive contained an **AAC audio track that was silent**. Presence of a stream is not evidence of spoken narration or speech suitable for automatic transcription. Do not identify or copy the third-party file in this PUBLIC repository.

## Implemented

- `gateway/qa_audio_window.py`: `sample_audio_fd(fd,seconds=8)`. An already trusted file descriptor is passed to `ffprobe_fd`; then a bounded `ffmpeg volumedetect` on only the first 1–15 seconds if exactly one recognized audio stream exists. Command uses a fixed argument vector and `/proc/self/fd/` with `pass_fds`, no URL or shell.
- Returns `NO_AUDIO_STREAM`, `SAMPLED_AUDIO_SILENT` for peak <= -55 dBFS, or `SAMPLED_AUDIO_ACTIVITY_UNVERIFIED`. None of these proves or detects actual human speech; all return `speech_verified=false` and `execution=DISABLED`. This **must not automatically authorize transcription or worker dispatch**.
- Unreadable/mutating media, invalid streams, unreviewed codecs, tool timeout, nonzero exit, malformed or out-of-range peak: fail closed.
- `tests/test_qa_audio_window.py`: 9 offline unit regressions PASS on `blueops-oci-worker-1`.
- `tests/smoke_qa_audio_window.py`: optional synthetic FFmpeg/FFprobe integration. Executed on the same worker, exit 0, result `PASS_SYNTHETIC_AUDIO_QA`. It generated temporary original 1s MP4s, removed automatically:
  - `no_track` => `NO_AUDIO_STREAM`;
  - `silence` => `SAMPLED_AUDIO_SILENT`, peak -91.0 dBFS;
  - `tone` => `SAMPLED_AUDIO_ACTIVITY_UNVERIFIED`, peak -17.6 dBFS.
  No network, third-party media, customer files, sample upload, live worker, n8n, or production modification.

## QA invocation

```bash
python3 -m unittest discover -s integrations/conexaoazul/tests -p "test_qa_audio_window.py" -v
python3 integrations/conexaoazul/tests/smoke_qa_audio_window.py
```

## Remaining risks and gates

- Sampling only the **first N seconds** cannot conclude whole-source silence; later speech may exist. The output label explicitly says `SAMPLED`.
- `volumedetect` estimates signal peak, not speech, audio quality, transcript accuracy or broadcast loudness; noise/music can show activity without spoken words.
- Must independently verify source rights, ownership, valid reviewer, private object-store version, tenant isolation, revocation and secure FFmpeg sandbox (network denied, resource bounds) before real QA media processing.
- No real locked-down worker or end-to-end Odoo video render exists in this change. Remain draft and NO PROD DEPLOY.
