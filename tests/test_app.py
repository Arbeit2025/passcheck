import importlib.util
import os
import string
import sys
import unittest

APP_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py"
)
spec = importlib.util.spec_from_file_location("passcheck_app", APP_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules["passcheck_app"] = mod
spec.loader.exec_module(mod)

SYMBOLS = set(mod.SYMBOLS)


class ScoreTest(unittest.TestCase):
    def test_weak_numeric_password_scores_lowest_band(self):
        r = mod.score_password("123456")
        self.assertLess(r["score"], 20)
        self.assertEqual(r["level"], 0)

    def test_common_word_password_scores_lowest_band(self):
        r = mod.score_password("password")
        self.assertLess(r["score"], 20)
        self.assertEqual(r["level"], 0)

    def test_strong_password_scores_highest_band(self):
        r = mod.score_password("Xk9#mQ2$vL8!pR4z")
        self.assertGreaterEqual(r["score"], 80)
        self.assertEqual(r["level"], 4)

    def test_medium_password_scores_middle_band(self):
        r = mod.score_password("Hello2024")
        self.assertGreaterEqual(r["score"], 40)
        self.assertLess(r["score"], 60)
        self.assertEqual(r["level"], 2)

    def test_sequence_and_repeat_are_penalized(self):
        seq = mod.score_password("abcd1234")
        plain = mod.score_password("axqz7391")
        self.assertLess(seq["score"], plain["score"])

    def test_entropy_grows_with_length(self):
        short = mod.score_password("aB3$")
        long = mod.score_password("aB3$aB3$aB3$aB3$")
        self.assertLess(short["entropy_bits"], long["entropy_bits"])
        self.assertGreater(long["entropy_bits"], 80)

    def test_empty_password(self):
        r = mod.score_password("")
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["entropy_bits"], 0.0)


class GenerateTest(unittest.TestCase):
    def test_generate_count_and_length(self):
        pws = mod.generate_passwords(16)
        self.assertEqual(len(pws), 5)
        for pw in pws:
            self.assertEqual(len(pw), 16)

    def test_generate_charset_constraints(self):
        pws = mod.generate_passwords(20, use_upper=False,
                                     use_digits=False, use_symbols=False)
        allowed = set(string.ascii_lowercase)
        for pw in pws:
            self.assertTrue(set(pw) <= allowed)

    def test_generate_includes_each_selected_class(self):
        for pw in mod.generate_passwords(16):
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in SYMBOLS for c in pw))

    def test_generate_length_is_clamped(self):
        self.assertTrue(all(len(pw) == 8 for pw in mod.generate_passwords(2)))
        self.assertTrue(all(len(pw) == 64 for pw in mod.generate_passwords(999)))


class WebTest(unittest.TestCase):
    def setUp(self):
        self.client = mod.app.test_client()

    def test_index_ok(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("passcheck", resp.get_data(as_text=True))

    def test_check_post_shows_score_without_echoing_password(self):
        secret_pw = "Zx9!uniqueMARKERpw"
        resp = self.client.post("/check", data={"password": secret_pw})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("点", body)
        self.assertNotIn(secret_pw, body)

    def test_generate_post_returns_five_candidates(self):
        resp = self.client.post("/generate", data={
            "length": "12", "lower": "on", "digits": "on"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertEqual(body.count('class="cand"'), 5)

    def test_api_generate(self):
        resp = self.client.get("/api/generate?length=12&symbols=false")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["length"], 12)
        self.assertEqual(len(data["passwords"]), 5)
        for pw in data["passwords"]:
            self.assertEqual(len(pw), 12)
            self.assertFalse(set(pw) & SYMBOLS)

    def test_api_generate_default_and_clamp(self):
        data = self.client.get("/api/generate").get_json()
        self.assertEqual(data["length"], 16)
        data = self.client.get("/api/generate?length=1000").get_json()
        self.assertEqual(data["length"], 64)

    def test_healthz(self):
        resp = self.client.get("/healthz")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
