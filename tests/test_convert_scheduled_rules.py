import os
from unittest import TestCase

from panther_classic_converter.converter.converter import convert_detection


dir_path = os.path.dirname(os.path.realpath(__file__))


class TestConvertRules(TestCase):
    def test_convert_vpc_dns_tunneling_query_snowflake(self) -> None:
        legacy_path = f"{dir_path}/testdata/snowflake_unusual_login_volume.yml"
        converted_path = (
            f"{dir_path}/testdata/snowflake_unusual_login_volume_converted.py"
        )
        result = convert_detection(legacy_path, False)
        with open(converted_path, "r") as converted:
            self.assertEqual(result, converted.read())
