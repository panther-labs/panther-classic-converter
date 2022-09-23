# nolint
from panther_config import detection, PantherEvent


def _aws_s3_bucket_policyallowwithnotprincipal_policy(resource: PantherEvent) -> bool:
    from policyuniverse.policy import Policy
    import json

    if resource["Policy"] is None:
        return True
    iam_policy = Policy(json.loads(resource["Policy"]))
    for statement in iam_policy.statements:
        if statement.effect == "Allow" and statement.uses_not_principal():
            return False
    return True


detection.Policy(
    policy_id="AWS.S3.Bucket.PolicyAllowWithNotPrincipal",
    ignore_patterns=None,
    resource_types=["AWS.S3.Bucket"],
    severity="HIGH",
    name="AWS S3 Bucket Policy Allow With Not Principal",
    filters=detection.PythonFilter(
        func=_aws_s3_bucket_policyallowwithnotprincipal_policy
    ),
    enabled=True,
    unit_tests=[
        detection.JSONUnitTest(
            data='""',
            name="Bucket Uses Allow With Principal",
            expect_match=True,
            mocks=[],
        ),
        detection.JSONUnitTest(
            data='""',
            name="Bucket Uses Allow With Not Principal",
            expect_match=False,
            mocks=[],
        ),
    ],
    tags=[
        "AWS",
        "Identity & Access Management",
        "Collection:Data From Cloud Storage Object",
    ],
    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html",
    runbook="https://docs.runpanther.io/alert-runbooks/built-in-policies/aws-s3-bucket-policy-does-not-use-allow-with-not-principal\n",
    description="Prevents the use of a 'Not' principal in conjunction with an allow effect in an S3 bucket policy, which would allow global access for the resource besides the principals specified.\n",
    reports={"MITRE ATT&CK": ["TA0009:T1530"]},
    destinations=None,
    alert_title=None,
    alert_context=None,
    alert_grouping=detection.AlertGrouping(period_minutes=15, group_by=None),
)
