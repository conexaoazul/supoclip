"""Offline tests for audio-stream/silent-window classification."""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.qa_audio_window import AudioWindowDenied, sample_audio_fd

VIDEO = {"codec_type": "video", "codec_name": "h264"}
AAC = {"codec_type": "audio", "codec_name": "aac"}


class AudioWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "synthetic.mp4"
        self.path.write_bytes(b"\x00\x00\x00\x18ftypisom" + b"x" * 128)
        self.fd = os.open(self.path, os.O_RDONLY)

    def tearDown(self):
        os.close(self.fd)
        self.tmp.cleanup()

    def checked(self, *, streams=None, stderr=b"max_volume: -91.0 dB\n",
                returncode=0):
        streams = [VIDEO, AAC] if streams is None else streams
        with patch("gateway.qa_audio_window.subprocess.run",
                   return_value=SimpleNamespace(
                       returncode=returncode, stderr=stderr)) as runner:
            result = sample_audio_fd(
                self.fd, probe_fn=lambda _: {"streams": streams})
        return result, runner

    def test_missing_audio_stream_does_not_run_meter(self):
        result, runner = self.checked(streams=[VIDEO])
        self.assertEqual(result["classification"], "NO_AUDIO_STREAM")
        self.assertFalse(result["audio_stream_present"])
        self.assertFalse(result["speech_verified"])
        runner.assert_not_called()

    def test_silent_aac_even_when_stream_exists(self):
        result, runner = self.checked()
        self.assertEqual(result["classification"], "SAMPLED_AUDIO_SILENT")
        self.assertEqual(result["peak_dbfs"], -91.0)
        self.assertFalse(result["speech_verified"])
        args = runner.call_args.args[0]
        self.assertEqual(args[args.index("-protocol_whitelist") + 1], "file")
        self.assertIn("/proc/self/fd/" + str(self.fd), args)
        self.assertEqual(runner.call_args.kwargs["pass_fds"], (self.fd,))
        self.assertEqual(runner.call_args.kwargs["timeout"], 25)

    def test_tone_is_not_verified_speech(self):
        result, _ = self.checked(stderr=b"max_volume: -12.0 dB\n")
        self.assertEqual(result["classification"],
                         "SAMPLED_AUDIO_ACTIVITY_UNVERIFIED")
        self.assertFalse(result["speech_verified"])

    def test_minus_infinity_silence(self):
        result, _ = self.checked(stderr=b"max_volume: -inf dB\n")
        self.assertEqual(result["classification"], "SAMPLED_AUDIO_SILENT")
        self.assertIsNone(result["peak_dbfs"])

    def test_meter_failures_are_not_audio_evidence(self):
        for stderr, code in (
            (b"", 0),
            (b"max_volume: -12.0 dB\n", 1),
            (b"max_volume: +1.0 dB\n", 0),
            (b"max_volume: -5.0 dB\nmax_volume: -4.0 dB\n", 0),
        ):
            with self.subTest(stderr=stderr, code=code):
                with self.assertRaises(AudioWindowDenied):
                    self.checked(stderr=stderr, returncode=code)

    def test_bad_stream_metadata(self):
        for streams in ([], [{}] * 17, [VIDEO, AAC, AAC],
                        [VIDEO, {"codec_type": "audio", "codec_name": "flac"}]):
            with self.subTest(streams=streams), self.assertRaises(AudioWindowDenied):
                self.checked(streams=streams)

    def test_bad_input_parameters(self):
        for seconds in (0, 16, -1, True, "8"):
            with self.subTest(seconds=seconds), self.assertRaises(AudioWindowDenied):
                sample_audio_fd(
                    self.fd, seconds=seconds,
                    probe_fn=lambda _: {"streams": [VIDEO, AAC]})
        with self.assertRaises(AudioWindowDenied):
            sample_audio_fd(-1, probe_fn=lambda _: {"streams": [VIDEO]})

    def test_timeout_is_failure(self):
        with patch("gateway.qa_audio_window.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["ffmpeg"], 25)):
            with self.assertRaisesRegex(AudioWindowDenied, "audio_meter_unavailable"):
                sample_audio_fd(
                    self.fd, probe_fn=lambda _: {"streams": [VIDEO, AAC]})

    def test_detect_in_place_file_mutation(self):
        def mutate(*_args, **_kwargs):
            with open(self.path, "ab") as out:
                out.write(b"changed")
            return SimpleNamespace(returncode=0, stderr=b"max_volume: -91.0 dB\n")
        with patch("gateway.qa_audio_window.subprocess.run",
                   side_effect=mutate):
            with self.assertRaisesRegex(
                    AudioWindowDenied, "media_changed_during_audio_probe"):
                sample_audio_fd(
                    self.fd, probe_fn=lambda _: {"streams": [VIDEO, AAC]})


if __name__ == "__main__":
    unittest.main()
