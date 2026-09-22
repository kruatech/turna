import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('wan', Path(__file__).with_name('af-xdp-wan.py'))
wan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wan)

class QueueGate(unittest.TestCase):
    def line(self, q, rx=10, tx=10, drops=0, final='true'):
        return f'AF_XDP queue stats queue={q} rx={rx} tx={tx} parse_drops=0 tx_drops={drops} final_snapshot={final}\n'

    def test_both_queues(self):
        self.assertTrue(wan.queue_gate(self.line(0) + self.line(1), [0, 1])[0])

    def test_idle_or_missing_queue(self):
        self.assertFalse(wan.queue_gate(self.line(0), [0, 1])[0])
        self.assertFalse(wan.queue_gate(self.line(0) + self.line(1, rx=0), [0, 1])[0])

    def test_drop_or_no_final(self):
        self.assertFalse(wan.queue_gate(self.line(0, drops=1), [0])[0])
        self.assertFalse(wan.queue_gate(self.line(0, final='false'), [0])[0])

class ResultGate(unittest.TestCase):
    def test_wan_threshold(self):
        d = dict(sent=10000, recv=9999, loss=1, errs=0, duration_s=100)
        self.assertTrue(wan.client_gate(d, 0, 100, 'media', 99.99)['pass'])
        self.assertFalse(wan.client_gate(d, 0, 100, 'media', 100)['pass'])
        d.update(recv=9998, loss=2)
        self.assertFalse(wan.client_gate(d, 0, 100, 'media', 99.99)['pass'])

    def test_churn_is_strict(self):
        d = dict(sent=10000, recv=9999, loss=1, errs=0, duration_s=900)
        self.assertFalse(wan.client_gate(d, 0, 900, 'churn', 99.99)['pass'])
        d.update(recv=10000, loss=0)
        self.assertTrue(wan.client_gate(d, 0, 900, 'churn', 99.99)['pass'])
        d['errs'] = 1
        self.assertFalse(wan.client_gate(d, 0, 900, 'churn', 99.99)['pass'])

    def test_incomplete_and_inconsistent(self):
        d = dict(sent=10000, recv=10000, loss=0, errs=0, duration_s=10)
        self.assertFalse(wan.client_gate(d, 0, 100, 'media', 99.99)['pass'])
        d.update(duration_s=100, recv=10001)
        self.assertFalse(wan.client_gate(d, 0, 100, 'media', 99.99)['pass'])

    def test_resources(self):
        rows = [dict(status='VmRSS: 44000 kB', fds=20) for _ in range(24)]
        self.assertTrue(wan.resource_gate(rows)['pass'])
        rows[-1]['fds'] = 23
        self.assertFalse(wan.resource_gate(rows)['pass'])
        rows[-1]['fds'] = 20
        for r in rows[12:]:
            r['status'] = 'VmRSS: 120000 kB'
        self.assertFalse(wan.resource_gate(rows)['pass'])

if __name__ == '__main__':
    unittest.main()
