"""Tests for the deterministic agent/workload integration seam."""

from __future__ import annotations

import unittest

from tcop.simulation import Cluster
from tcop.workloads import DeterministicAgentWorkload


class DeterministicWorkloadTests(unittest.TestCase):
    def test_tool_fact_becomes_scoped_signed_observation(self) -> None:
        cluster = Cluster()
        try:
            workload = DeterministicAgentWorkload(cluster, "agent-1")
            observation = workload.prohibited_export()
            self.assertEqual("tool.prohibited_export", observation["observation_type"])
            self.assertEqual(["tool:data.export"], observation["scope"])
            results = cluster.disseminate("node-1", observation)
            self.assertTrue(all(result.accepted for result in results))
        finally:
            cluster.close()
