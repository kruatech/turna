import unittest
from transport_network_result import assess


class AcceptanceTests(unittest.TestCase):
    def result(self, acceptance="strict", transport="quic", **changes):
        result = dict(schema_version=2, sent=3000, recv=3000, errs=0, duration_s=300,
                      completed=True, peak_in_flight=2, missing_echoes=0,
                      echo_timeouts=0, late_echoes=0, pending_at_end=0, exit_code=0)
        result.update(changes)
        return assess(result, 300, 10, transport, acceptance)

    def test_clean_run_passes(self):
        self.assertTrue(self.result()['pass'])

    def test_full_duration_loss_is_stable_but_not_pass(self):
        r = self.result(recv=2999, missing_echoes=1, echo_timeouts=1, exit_code=1)
        self.assertTrue(r['stability_pass'])
        self.assertTrue(r['rate_pass'])
        self.assertFalse(r['delivery_pass'])
        self.assertFalse(r['pass'])

    def test_late_echo_cannot_hide_deadline_failure(self):
        r = self.result(echo_timeouts=1, late_echoes=1, exit_code=1)
        self.assertTrue(r['stability_pass'])
        self.assertFalse(r['pass'])

    def test_operational_errors_and_early_stop_fail_stability(self):
        for changes in [dict(errs=1, exit_code=1), dict(completed=False), dict(duration_s=176),
                        dict(exit_code=124), dict(pending_at_end=2)]:
            self.assertFalse(self.result(**changes)['stability_pass'])

    def test_low_volume_stays_fail(self):
        r = self.result(sent=2900, recv=2900)
        self.assertTrue(r['stability_pass'])
        self.assertFalse(r['rate_pass'])
        self.assertFalse(r['pass'])

    def test_old_or_inconsistent_reports_cannot_pass(self):
        for changes in [dict(schema_version=1), dict(recv=3001), dict(missing_echoes=2),
                        dict(sent=None), dict(duration_s=float('nan'))]:
            self.assertFalse(self.result(**changes)['pass'])

    def test_explicit_transport_policy_preserves_delivery_failure(self):
        for transport in ('quic', 'wt'):
            r = self.result(acceptance='transport', transport=transport,
                            recv=2999, missing_echoes=1, echo_timeouts=1, exit_code=1)
            self.assertTrue(r['pass'])
            self.assertFalse(r['delivery_pass'])
            self.assertFalse(r['strict_pass'])

    def test_sctp_cannot_bypass_delivery(self):
        self.assertFalse(self.result(acceptance='transport', transport='sctp',
                         recv=2999, missing_echoes=1, echo_timeouts=1, exit_code=1)['pass'])

    def test_transport_policy_does_not_hide_errors_blackout_or_low_rate(self):
        for changes in (dict(errs=1, exit_code=1), dict(completed=False),
                        dict(exit_code=124), dict(sent=2900, recv=2900),
                        dict(recv=0, missing_echoes=3000, echo_timeouts=3000, exit_code=1)):
            self.assertFalse(self.result(acceptance='transport', **changes)['pass'])

    def test_zero_media_is_not_delivery_pass(self):
        r = self.result(sent=0, recv=0, peak_in_flight=0)
        self.assertFalse(r['delivery_pass'])
        self.assertFalse(r['pass'])

    def test_bad_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            self.result(acceptance='anything')


if __name__ == '__main__':
    unittest.main()
