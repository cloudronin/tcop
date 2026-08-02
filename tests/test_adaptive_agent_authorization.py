from __future__ import annotations
import tempfile, unittest
from pathlib import Path
from tcop.adaptive_agent_authorization import run_adaptive_authorization, verify_adaptive_authorization
class AdaptiveAuthorizationTests(unittest.TestCase):
 def test_strict_replay_has_exactly_one_hundred_episodes(self)->None:
  with tempfile.TemporaryDirectory() as t:
   value=run_adaptive_authorization(Path(t)/"study")
   self.assertEqual(value["episodes"],100);self.assertTrue(value["byte_stable"]);self.assertTrue(verify_adaptive_authorization(Path(t)/"study")["valid"])
