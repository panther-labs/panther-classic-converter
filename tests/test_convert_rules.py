import os
from unittest import TestCase

from panther_classic_converter.converter.converter import convert_detection


dir_path = os.path.dirname(os.path.realpath(__file__))


class TestConvertRules(TestCase):
    def test_convert_brute_force_by_ip(self) -> None:
        legacy_path = f"{dir_path}/testdata/brute_force_by_ip.yml"
        converted_path = f"{dir_path}/testdata/brute_force_by_ip_converted.py"
        result = convert_detection(legacy_path, False)
        with open(converted_path, "r") as converted:
            self.assertEqual(result, converted.read())
