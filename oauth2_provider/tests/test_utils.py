import unittest

class TestUtils(unittest.TestCase):
    def test_gen_api_key_length(self):
        from oauth2_provider.utils import gen_api_key

        ten = gen_api_key(length=10)
        five = gen_api_key(length=5)
        fourty_two = gen_api_key(length=42)

        assert len(ten) == 10
        assert len(five) == 5
        assert len(fourty_two) == 42

    def test_gen_api_valid_strings(self):
        from oauth2_provider.utils import gen_api_key
        import urllib

        ten = gen_api_key(length=10)
        five = gen_api_key(length=5)
        fourty_two = gen_api_key(length=42)

        assert urllib.quote_plus(ten) == ten
        assert urllib.quote_plus(five) == five
        assert urllib.quote_plus(fourty_two) == fourty_two




