import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('resume_after_limit', Path(__file__).resolve().parents[1] / 'build/resume_after_limit.py')
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumptionTests(unittest.TestCase):
    def test_only_structured_usage_limit_is_retryable(self):
        self.assertTrue(resume.usage_error({'codex_error_info': 'usage_limit_exceeded'}))
        self.assertFalse(resume.usage_error({'message': 'usage limit exceeded'}))
        self.assertFalse(resume.usage_error({'codex_error_info': 'connection_failed'}))

    def test_exhausted_windows_use_latest_server_reset(self):
        rates = {'primary': {'used_percent': 100, 'resets_at': 200},
                 'secondary': {'used_percent': 100, 'resets_at': 300}}
        self.assertEqual(resume.reset_time({}, rates, '', 'UTC'), 300)

    def test_nonexhausted_window_is_not_a_reset_instruction(self):
        with self.assertRaises(ValueError):
            resume.reset_time({}, {'primary': {'used_percent': 48, 'resets_at': 200}}, '', 'UTC')

    def test_recorded_dated_limit_message(self):
        error = {'message': 'You’ve hit your usage limit. Try again at Oct 22nd, 2026 12:18 AM.'}
        value = resume.reset_time(error, {}, '2026-10-22T05:47:49Z', 'America/Los_Angeles')
        self.assertEqual(dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat(), '2026-10-22T07:18:00+00:00')

    def test_recorded_time_only_limit_message(self):
        error = {'message': 'You’ve hit your usage limit. Try again at 1:21 PM.'}
        value = resume.reset_time(error, {}, '2026-10-19T15:42:33Z', 'America/Los_Angeles')
        self.assertEqual(dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat(), '2026-10-19T20:21:00+00:00')

    def test_missing_reset_stops(self):
        with self.assertRaises(ValueError):
            resume.reset_time({'message': 'Usage limit exceeded'}, {}, '2026-10-22T00:00:00Z', 'UTC')


if __name__ == '__main__':
    unittest.main()
