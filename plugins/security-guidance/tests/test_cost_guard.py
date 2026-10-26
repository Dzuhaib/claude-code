import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "hooks"
sys.path.insert(0, str(HOOKS))

import llm


class CostGuardTest(unittest.TestCase):
    def setUp(self):
        self.original_max = llm._MAX_API_CALLS
        self.original_calls = llm._API_CALLS
        llm._API_CALLS = 0

    def tearDown(self):
        llm._MAX_API_CALLS = self.original_max
        llm._API_CALLS = self.original_calls

    def test_reserves_calls_up_to_budget(self):
        llm._MAX_API_CALLS = 2
        self.assertTrue(llm._reserve_api_call())
        self.assertTrue(llm._reserve_api_call())
        self.assertFalse(llm._reserve_api_call())

    def test_zero_budget_blocks_every_call(self):
        llm._MAX_API_CALLS = 0
        self.assertFalse(llm._reserve_api_call())
        self.assertEqual(llm._API_CALLS, 0)


if __name__ == "__main__":
    unittest.main()
