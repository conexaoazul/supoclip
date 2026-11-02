# Blue AI Video Studio — comparative video QA protocol (P0 / NOT RUN)

**Status:** pre-registration of a future test plan, 2026-11-01.
**No videos have been processed or measured by this PR.**
**QA only:** no production resources, customer media or public social posts.

## Engines under comparison

| Engine | Source | License | Test mode |
| --- | --- | --- | --- |
| SupoClip | https://github.com/conexaoazul/supoclip | AGPL-3.0 | private self-hosted QA candidate; project pin `4bc76f83b3427808464f117473ee61083c65cf1f` until updated by review |
| AutoClip | https://github.com/artbyjazi/autoclip | MIT | optional isolated challenger; pin a specific SHA after review, do **not** deploy a floating `main` |

AutoClip's upstream README describes Python 3.11/3.12 (not 3.13),
FFmpeg with libass/libx264, local Whisper/Ollama mode, and unverified
golden-set reframe quality. Confirm the current release, CVEs, license and
dependencies before a real comparison. Neither tool is integrated here.

## Inputs and access gate

Use three independently owned or specifically licensed, **uploaded** video
files, not YouTube downloads or any customer's unattended live video.

| Case | Content | Min scope | Reason |
| --- | --- | --- | --- |
| A | One presenter, clean audio, PT-BR | 5–10 minutes | baseline captions, word timing, hook relevance |
| B | Two speakers, interview, PT-BR | 10–20 minutes | diarization, reframing, speaker fairness |
| C | Internal product demo, terminology, PT-BR | 5–15 minutes | jargon fidelity, screen legibility, pacing |

Before media enters a container, record for each source: internal opaque ID,
owner/rights proof and retention/allowed-use terms, SHA-256, local ffprobe
duration, bytes, resolution, framerate and sample rate, privacy classification,
and reviewer name/approval ID. Store private evidence and files **outside Git**.
Preflight must deny unsupported rights, unverified duration, out-of-policy
metadata and URLs needing unmanaged network egress.

## Fair experiment

- Same input file bytes and verified hashes for each engine.
- Same three cases, target aspect ratio 9:16, target 1080x1920, H.264/AAC;
  note exact fallbacks if an engine cannot support a target.
- Fix model/provider versions, CPU/GPU allocation, container image digests,
  cost ceilings, timeout budget, cache cold/warm state and max 10 clips.
- If only one engine has a capability (e.g. semantic ranking or custom
  subtitle theme), score it separately and note non-comparability.
- Randomize blind editorial review order, 2 independent PT-BR reviewers,
  report disagreement and preserve both individual scores.
- Do **not** fabricate A/B performance by showing example screenshots or
  test suite counts. Offline tests prove contract behavior, not render quality.
- Run each case at least twice per engine to estimate repeatability. Exact
  retry policy and cases must be recorded to avoid cherry-picking.

## Evidence and scoring

Keep one inspectable record per input × engine × repetition with columns:

`case_id,engine,source_sha256,engine_sha,image_digest,run_id,
status,wall_seconds,media_input_seconds,processed_clips,
approved_clips,cpu_seconds,peak_rss_mb,peak_disk_mb,egress_mb,
asr_provider,llm_provider,asr_cost_brl,llm_cost_brl,
compute_cost_brl,storage_egress_cost_brl,review_minutes,
legal_rights_ref,reviewer_a_id,reviewer_b_id,caption_accuracy_1to5,
caption_timing_1to5,hook_relevance_1to5,reframe_1to5,
brand_consistency_1to5,privacy_rights_pass,
tenant_isolation_pass,source_probe_pass,audit_trace_ref`

Primary KPI: `total_direct_cost_brl / approved_clips` (undefined if zero
approved clips). Cost includes external model charges, compute time, storage,
egress, and an **explicit** separately reported human review cost. Do not
confuse cost per rendered clip with cost per **accepted** clip.

Secondary KPIs: percentage of 5-point editorial scores >= 4, clips approved
per hour of source, PT-BR caption accuracy, latency per input minute, peak
CPU/RAM/disk, failed/timeout rate and number of unresolved legal/privacy
gates. For quality, report median and range by case, never one global
unexplained average.

### Decision gates (proposals, not achieved)

1. **Hard deny:** unlicensed source, privacy/tenant isolation failure,
   unaudited external sending, unsigned backend authentication, secrets
   exposure or uncontrolled egress.
2. **Technical:** all six benchmark executions × both engines finish, or
   failures are reported transparently with root cause.
3. **Quality:** each case receives a blinded review; baseline target at least
   80% of approved clips have median caption/reframe/hook score >= 4/5.
4. **Economics:** documented unit cost per approved clip and an upper-bound
   budget/threshold approved by commercial owner **before model calls**.
5. **Operational:** replay-safe queue, cancel/closure semantics, storage TTL,
   traceable human signoff, and private output.
6. **Commercial:** validate conversion of a full source to editorial-approved
   media and measurable campaign impact; *do not claim uplift without data*.

## Follow-up ownership

- Engineering/Security: isolate QA infrastructure, complete SSRF/egress and
  object ACL proof, verify reproducibility, collect cost and logs.
- Editorial/Marketing: define golden moments, rating rubric, brand assets,
  2 reviewers, rights evidence, no external publication.
- Finance/Product: approve spending cap, calculate gross margin by deliverable.
- Legal: review SupoClip AGPL-3.0 service obligations and AutoClip MIT notices.

The engine with the best **quality-adjusted unit cost and acceptable risk**
may be selected as a pluggable adapter. **No engine winner has been measured.**
