# nolint
from panther_sdk import detection, PantherEvent


def _snowflake_unusualloginvolume_rule(_: PantherEvent) -> bool:
    return True


def _snowflake_unusualloginvolume_title(event: PantherEvent) -> str:
    return (
        f"{event.get('user_name')} has exceeded the normal amount of Snowflake logins"
    )


detection.ScheduledRule(
    rule_id="Snowflake.UnusualLoginVolume",
    severity="LOW",
    threshold=0,
    name="Unusual Volume of Snowflake Logins Detected",
    scheduled_queries=["Query.Snowflake.UnusualLoginVolume"],
    filters=detection.PythonFilter(func=_snowflake_unusualloginvolume_rule),
    enabled=False,
    unit_tests=[
        detection.JSONUnitTest(
            data='{"user_name": "testuser", "count(user_name)": 100}',
            name="Unusual Login Volume",
            expect_match=True,
            mocks=[],
        )
    ],
    tags=["Snowflake", "Lateral Movement:Exploitation of Remote Services"],
    reference="",
    runbook="",
    description="Alerts when the number of logins to Snowflake exceeds a baselined threshold\n",
    summary_attrs=[],
    reports={"MITRE ATT&CK": ["TA0008:T1210"]},
    destinations=None,
    alert_title=_snowflake_unusualloginvolume_title,
    alert_context=None,
    alert_grouping=detection.AlertGrouping(period_minutes=15, group_by=None),
)
