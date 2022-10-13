# nolint
def use():
    from panther_config import detection, PantherEvent

    def _standard_bruteforcebyip_rule(event: PantherEvent) -> bool:
        import panther_event_type_helpers as event_type

        return event.udm("event_type") == event_type.FAILED_LOGIN

    def _standard_bruteforcebyip_title(event: PantherEvent) -> str:
        from panther import lookup_aws_account_name

        log_type = event.get("p_log_type")
        title_str = f"{log_type}: User [{event.udm('actor_user')}] has exceeded the failed logins threshold"
        if log_type == "AWS.CloudTrail":
            title_str += (
                f" in [{lookup_aws_account_name(event.get('recipientAccountId'))}]"
            )
        return title_str

    def _standard_bruteforcebyip_alert_context(event: PantherEvent) -> dict:
        from panther_oss_helpers import add_parse_delay, geoinfo_from_ip
        from json import loads

        geoinfo = geoinfo_from_ip(event.udm("source_ip"))
        if isinstance(geoinfo, str):
            geoinfo = loads(geoinfo)
        context = {}
        context[
            "geolocation"
        ] = f"{geoinfo.get('city')}, {geoinfo.get('region')} in {geoinfo.get('country')}"
        context["ip"] = geoinfo.get("ip")
        context["reverse_lookup"] = geoinfo.get(
            "hostname", "No reverse lookup hostname"
        )
        context["ip_org"] = geoinfo.get("org", "No organization listed")
        context = add_parse_delay(event, context)
        return context

    detection.Rule(
        rule_id="Standard.BruteForceByIP",
        severity="MEDIUM",
        threshold=5,
        name="Brute Force By IP",
        log_types=[
            "Asana.Audit",
            "Atlassian.Audit",
            "AWS.CloudTrail",
            "Box.Event",
            "GSuite.Reports",
            "Okta.SystemLog",
            "OneLogin.Events",
            "OnePassword.SignInAttempt",
        ],
        filters=detection.PythonFilter(func=_standard_bruteforcebyip_rule),
        enabled=True,
        unit_tests=[
            detection.JSONUnitTest(
                data='{"eventVersion": "1.05", "userIdentity": {"type": "IAMUser", "principalId": "1111", "arn": "arn:aws:iam::123456789012:user/tester", "accountId": "123456789012", "userName": "testuser"}, "eventTime": "2019-01-01T00:00:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddress": "111.111.111.111", "userAgent": "Mozilla", "requestParameters": null, "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/", "MobileVersion": "No", "MFAUsed": "No"}, "eventID": "1", "eventType": "AwsConsoleSignIn", "recipientAccountId": "123456789012", "p_log_type": "AWS.CloudTrail", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="AWS.CloudTrail - Successful Login",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"eventVersion": "1.05", "userIdentity": {"type": "IAMUser", "principalId": "1111", "arn": "arn:aws:iam::123456789012:user/tester", "accountId": "123456789012", "userName": "tester"}, "eventTime": "2019-01-01T00:00:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "awsRegion": "us-east-1", "sourceIPAddress": "111.111.111.111", "userAgent": "Mozilla", "requestParameters": null, "responseElements": {"ConsoleLogin": "Failure"}, "additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/", "MobileVersion": "No", "MFAUsed": "No"}, "eventID": "1", "eventType": "AwsConsoleSignIn", "recipientAccountId": "123456789012", "p_log_type": "AWS.CloudTrail", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="AWS.CloudTrail - Failed Login",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"type": "event", "additional_details": "{\\"key\\": \\"value\\"}", "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"}, "ip_address": "111.111.111.111", "event_type": "DELETE", "p_log_type": "Box.Event", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Box - Regular Event",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"type": "event", "additional_details": "{\\"key\\": \\"value\\"}", "created_by": {"id": "12345678", "type": "user", "login": "cat@example", "name": "Bob Cat"}, "event_type": "FAILED_LOGIN", "source": {"id": "12345678", "type": "user", "name": "Bob Cat"}, "ip_address": "111.111.111.111", "p_log_type": "Box.Event", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Box - Login Failed",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"id": {"applicationName": "login"}, "ipAddress": "111.111.111.111", "events": [{"type": "login", "name": "login_success"}], "p_log_type": "GSuite.Reports", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="GSuite - Normal Login Event",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"actor": {"email": "bob@example.com"}, "id": {"applicationName": "login"}, "ipAddress": "111.111.111.111", "events": [{"type": "login", "name": "login_failure"}], "p_log_type": "GSuite.Reports", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="GSuite - Failed Login Event",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"actor": {"alternateId": "admin", "displayName": "unknown", "id": "unknown", "type": "User"}, "client": {"ipAddress": "111.111.111.111"}, "eventType": "user.session.start", "outcome": {"reason": "VERIFICATION_ERROR", "result": "SUCCESS"}, "p_log_type": "Okta.SystemLog", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Okta - Successful Login",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"actor": {"alternateId": "admin", "displayName": "unknown", "id": "unknown", "type": "User"}, "client": {"ipAddress": "111.111.111.111"}, "eventType": "user.session.start", "outcome": {"reason": "VERIFICATION_ERROR", "result": "FAILURE"}, "p_log_type": "Okta.SystemLog", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Okta - Failed Login",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"event_type_id": 8, "actor_user_id": 123456, "actor_user_name": "Bob Cat", "user_id": 123456, "user_name": "Bob Cat", "ipaddr": "111.111.111.111", "p_log_type": "OneLogin.Events", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="OneLogin - Normal Login Event",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"event_type_id": 6, "actor_user_id": 123456, "actor_user_name": "Bob Cat", "user_id": 123456, "user_name": "Bob Cat", "ipaddr": "1.2.3.4", "p_log_type": "OneLogin.Events", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="OneLogin - Failed Login Event",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"protoPayload": {"at_sign_type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "cloudresourcemanager.googleapis.com", "methodName": "SetIamPolicy", "authenticationInfo": {"principalEmail": "bob@example.com"}, "requestMetadata": {"callerIP": "111.111.111.111"}, "serviceData": {"@type": "type.googleapis.com/google.iam.v1.logging.AuditData", "policyDelta": {"bindingDeltas": [{"action": "ADD", "member": "cat@example.com", "role": "roles/resourcemanager.organizationAdmin"}]}}}, "p_log_type": "GCP.AuditLog", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="GCP - Non Login Event",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"actor": {"actor_type": "user", "email": "homer@springfield.com", "gid": "2222222", "name": "Homer"}, "context": {"client_ip_address": "8.8.8.8", "context_type": "web"}, "created_at": "2021-10-21T23:38:10.364Z", "details": {"method": ["ONE_TIME_KEY"]}, "event_category": "logins", "event_type": "user_login_failed", "gid": "222222222", "resource": {"email": "homer@springfield.com", "gid": "2222222", "name": "homer", "resource_type": "user"}, "p_log_type": "Asana.Audit", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Asana - Failed Login",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
            detection.JSONUnitTest(
                data='{"actor": {"actor_type": "user", "email": "homer@springfield.com", "gid": "2222222", "name": "Homer"}, "context": {"client_ip_address": "8.8.8.8", "context_type": "web"}, "created_at": "2021-10-21T23:38:10.364Z", "details": {"method": ["ONE_TIME_KEY"]}, "event_category": "logins", "event_type": "user_login_succeeded", "gid": "222222222", "resource": {"email": "homer@springfield.com", "gid": "2222222", "name": "homer", "resource_type": "user"}, "p_log_type": "Asana.Audit", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="Asana - Normal Login",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"uuid": "1234", "session_uuid": "5678", "timestamp": "2021-12-03 19:52:52", "category": "success", "type": "credentials_ok", "country": "US", "target_user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "1234"}, "client": {"app_name": "1Password Browser Extension", "app_version": "20184", "ip_address": "1.1.1.1", "os_name": "Solaris", "os_version": "10", "platform_name": "Chrome", "platform_version": "96.0.4664.55"}, "p_log_type": "OnePassword.SignInAttempt"}',
                name="1Password - Regular Login",
                expect_match=False,
                mocks=[],
            ),
            detection.JSONUnitTest(
                data='{"uuid": "1234", "session_uuid": "5678", "timestamp": "2021-12-03 19:52:52", "category": "credentials_failed", "type": "password_secret_bad", "country": "US", "target_user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "1234"}, "client": {"app_name": "1Password Browser Extension", "app_version": "20184", "ip_address": "111.111.111.111", "os_name": "Solaris", "os_version": "10", "platform_name": "Chrome", "platform_version": "96.0.4664.55"}, "p_log_type": "OnePassword.SignInAttempt", "p_parse_time": "2021-06-04 10:02:33.650807", "p_event_time": "2021-06-04 09:59:53.650807"}',
                name="1Password - Failed Login",
                expect_match=True,
                mocks=[
                    detection.UnitTestMock(
                        name="geoinfo_from_ip",
                        return_value='{ "ip": "111.111.111.111", "region": "UnitTestRegion", "city": "UnitTestCityNew", "country": "UnitTestCountry", "hostname": "somedomain.com", "org": "Some Org" }',
                    )
                ],
            ),
        ],
        tags=["DataModel", "Credential Access:Brute Force"],
        reference="",
        runbook="Analyze the IP they came from, and other actions taken before/after. Check if a user from this ip eventually authenticated successfully.",
        description="An actor user was denied login access more times than the configured threshold.",
        summary_attrs=["p_any_ip_addresses"],
        reports={"MITRE ATT&CK": ["TA0006:T1110"]},
        destinations=None,
        alert_title=_standard_bruteforcebyip_title,
        alert_context=_standard_bruteforcebyip_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60, group_by=None),
    )
