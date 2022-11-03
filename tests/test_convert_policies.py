import os
from unittest import TestCase

from panther_classic_converter.converter.converter import convert_detection


dir_path = os.path.dirname(os.path.realpath(__file__))


class TestConvertedPolicies(TestCase):
    def test_convert_aws_s3_bucket_policy_allow_with_not_principal(self) -> None:
        legacy_path = (
            f"{dir_path}/testdata/aws_s3_bucket_policy_allow_with_not_principal.yml"
        )
        converted_path = f"{dir_path}/testdata/aws_s3_bucket_policy_allow_with_not_principal_converted.py"
        result = convert_detection(legacy_path, False)
        with open(converted_path, "r") as converted:
            self.assertEqual(result, converted.read())
