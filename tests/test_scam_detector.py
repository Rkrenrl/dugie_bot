import unittest

from scam_detector import detect_scam


class ScamDetectorTests(unittest.TestCase):
    def test_flags_mrbeast_giveaway_copy(self):
        result = detect_scam("MRBEAST $10,000 GIVEAWAY! Click to claim your prize")
        self.assertTrue(result.is_scam)
        self.assertIn("MrBeast giveaway branding", result.reasons)

    def test_flags_free_nitro_offer(self):
        result = detect_scam("Claim your free Discord Nitro now")
        self.assertTrue(result.is_scam)

    def test_flags_suspicious_gift_domain(self):
        result = detect_scam("Free Nitro: https://discord-nitro-rewards.example/claim")
        self.assertTrue(result.is_scam)

    def test_does_not_flag_ordinary_mrbeast_discussion(self):
        result = detect_scam("I watched a MrBeast video yesterday")
        self.assertFalse(result.is_scam)

    def test_does_not_flag_ordinary_nitro_discussion(self):
        result = detect_scam("Discord Nitro is a paid subscription")
        self.assertFalse(result.is_scam)


if __name__ == "__main__":
    unittest.main()