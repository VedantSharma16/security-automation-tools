import unittest

from log_triage_agent.knowledge_base import AttackKnowledgeBase


class TestAttackKnowledgeBase(unittest.TestCase):
    def setUp(self):
        self.kb = AttackKnowledgeBase()

    def test_retrieves_brute_force_techniques(self):
        techniques = self.kb.retrieve_for_finding(
            "brute_force", "5 failed login attempts from 203.0.113.5"
        )
        ids = {t.id for t in techniques}
        self.assertIn("T1110", ids)
        self.assertIn("T1110.001", ids)

    def test_retrieves_password_spray_technique(self):
        techniques = self.kb.retrieve_for_finding("password_spray", "distinct usernames")
        ids = {t.id for t in techniques}
        self.assertIn("T1110.003", ids)

    def test_unknown_finding_type_returns_empty(self):
        techniques = self.kb.retrieve_for_finding("not_a_real_finding_type", "")
        self.assertEqual(techniques, [])

    def test_results_are_ranked_by_score_descending(self):
        techniques = self.kb.retrieve_for_finding(
            "credential_success_after_failures", "compromised valid account credentials"
        )
        scores = [t.score for t in techniques]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_free_text_search_finds_relevant_technique(self):
        results = self.kb.search("password spraying many accounts")
        self.assertTrue(any(t.id == "T1110.003" for t in results))


if __name__ == "__main__":
    unittest.main()
