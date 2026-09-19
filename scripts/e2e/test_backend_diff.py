"""Exercise runner verdicts using fake processes; no io_uring claim."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('backend_diff.sh')

class RunnerTests(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / 'scripts/e2e/backend_diff.sh'
            script.parent.mkdir(parents=True)
            shutil.copyfile(SCRIPT, script)
            bindir = root / 'bin'
            bindir.mkdir()
            node = root / 'target/release/turna-node'
            node.parent.mkdir(parents=True)
            node.write_text('''#!/usr/bin/env python3
import os,signal,time,sys
if os.environ['CASE']=='startup': sys.exit(1)
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
while True: time.sleep(.02)
''')
            cargo = bindir / 'cargo'
            cargo.write_text('''#!/bin/sh
[ "$1" = build ] && exit 0
case "$CASE" in
fail) echo 'test result: FAILED'; exit 1;;
zero) echo 'test result: ok. 0 passed; 0 failed; 0 ignored;';;
skip) echo 'SKIP: Allocate failed'; echo 'test result: ok. 1 passed; 0 failed; 0 ignored;';;
*) echo 'test result: ok. 1 passed; 0 failed; 0 ignored;';;
esac
''')
            curl = bindir / 'curl'
            curl.write_text('#!/bin/sh\nsleep 0.1\n[ "$CASE" = startup ] && exit 1\nprintf "{}\\n"\n')
            for p in (node, cargo, curl): p.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'],
                       CASE=mode, OUT='result', START_TIMEOUT='1', TEST_FILTER='turn_allocate',
                       BACKENDS='tokio io_uring', TARGET='127.0.0.1:13478',
                       HEALTH_URL='http://127.0.0.1:19098/ready')
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True, timeout=20)
            self.assertTrue((root/'result/tokio.node.log').exists())
            self.assertTrue((root/'result/io_uring.node.log').exists())
            return result

    def test_both_pass(self): self.assertEqual(self.run_case('pass').returncode, 0)
    def test_equal_failures_fail(self): self.assertNotEqual(self.run_case('fail').returncode, 0)
    def test_zero_tests_fail(self): self.assertNotEqual(self.run_case('zero').returncode, 0)
    def test_silent_skip_fails(self): self.assertNotEqual(self.run_case('skip').returncode, 0)
    def test_equal_startup_failures_fail(self): self.assertNotEqual(self.run_case('startup').returncode, 0)

if __name__ == '__main__': unittest.main()
