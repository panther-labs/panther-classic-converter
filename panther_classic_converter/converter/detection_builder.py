# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast
import json
from typing import Union, Any, Optional

from panther_sdk import detection

from .name_fixer import UpdatedFunctionNames


def append_detection(
    tree: ast.Module, yaml_config: dict, names: UpdatedFunctionNames, is_athena: bool
) -> None:
    detections_builder = DetectionBuilder(
        yaml_config=yaml_config,
        names=names,
        is_athena=is_athena,
    )
    tree.body.append(detections_builder.return_expr())


class DetectionBuilder:
    def __init__(
        self, yaml_config: dict, names: UpdatedFunctionNames, is_athena: bool
    ) -> None:
        self._yaml_result = yaml_config
        self._names = names
        self._detection_type = self._yaml_result["AnalysisType"]
        self._is_athena = is_athena

    def to_string(self) -> str:
        return ast.unparse(self.return_expr())

    def return_expr(self) -> ast.Expr:
        val_func = {
            "rule": self._rule_call,
            "policy": self._policy_call,
            "scheduled_rule": self._scheduled_rule_call,
            "scheduled_query": self._scheduled_query_call,
        }.get(self._detection_type, None)
        if val_func is None:
            raise Exception("unsupported analysis type")
        return ast.Expr(
            value=val_func(),
        )

    def _rule_call(self) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="Rule",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                self._rule_id_keyword(),
                self._severity_keyword(),
                self._threshold_keyword(),
                self._name_keyword(),
                self._log_types_keyword(),
                self._filters_keyword(),
                self._enabled_keyword(),
                self._unit_tests_keyword(),
                self._tags_keyword(),
                self._reference_keyword(),
                self._runbook_keyword(),
                self._description_keyword(),
                self._summary_attrs_keyword(),
                self._reports_keyword(),
                self._destinations_keyword(),
                self._alert_title_keyword(),
                self._alert_context_keyword(),
                self._alert_grouping_keyword(),
            ],
        )

    def _policy_call(self) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="Policy",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                self._policy_id_keyword(),
                self._ignore_patterns_keyword(),
                self._resource_types_keyword(),
                self._severity_keyword(),
                self._name_keyword(),
                self._filters_keyword(),
                self._enabled_keyword(),
                self._unit_tests_keyword(),
                self._tags_keyword(),
                self._reference_keyword(),
                self._runbook_keyword(),
                self._description_keyword(),
                self._reports_keyword(),
                self._destinations_keyword(),
                self._alert_title_keyword(),
                self._alert_context_keyword(),
                self._alert_grouping_keyword(),
            ],
        )

    def _scheduled_rule_call(self) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="ScheduledRule",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                self._rule_id_keyword(),
                self._severity_keyword(),
                self._threshold_keyword(),
                self._name_keyword(),
                self._scheduled_queries_keyword(),
                self._filters_keyword(),
                self._enabled_keyword(),
                self._unit_tests_keyword(),
                self._tags_keyword(),
                self._reference_keyword(),
                self._runbook_keyword(),
                self._description_keyword(),
                self._summary_attrs_keyword(),
                self._reports_keyword(),
                self._destinations_keyword(),
                self._alert_title_keyword(),
                self._alert_context_keyword(),
                self._alert_grouping_keyword(),
            ],
        )

    def _scheduled_query_call(self) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="ScheduledQuery",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                self._name_keyword(),
                self._enabled_keyword(),
                self._tags_keyword(),
                self._description_keyword(),
                self._sql_keyword(),
            ],
        )

    def _rule_id_keyword(self) -> ast.keyword:
        rule_id = self._yaml_result["RuleID"]
        return ast.keyword(arg="rule_id", value=ast.Constant(value=rule_id))

    def _policy_id_keyword(self) -> ast.keyword:
        policy_id = self._yaml_result["PolicyID"]
        return ast.keyword(arg="policy_id", value=ast.Constant(value=policy_id))

    def _severity_keyword(self) -> ast.keyword:
        severity = severity_to_enum(self._yaml_result.get("Severity", ""))
        value: Any
        if self._names.severity_func_name is not None:
            value = self._dynamic_string_call_value(
                self._names.severity_func_name, severity
            )
        else:
            value = ast.Constant(value=severity)
        return ast.keyword(
            arg="severity",
            value=value,
        )

    def _threshold_keyword(self) -> ast.keyword:
        threshold = self._yaml_result.get("Threshold", 0)
        return ast.keyword(
            arg="threshold",
            value=ast.Constant(value=threshold),
        )

    def _name_keyword(self) -> ast.keyword:
        if self._detection_type == "scheduled_query":
            name = self._yaml_result.get("QueryName", "")
        else:
            name = self._yaml_result.get("DisplayName", "")
        return ast.keyword(
            arg="name",
            value=ast.Constant(value=name),
        )

    def _filters_keyword(self) -> ast.keyword:
        return ast.keyword(
            arg="filters",
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="detection", ctx=ast.Load()),
                    attr="PythonFilter",
                    ctx=ast.Load(),
                ),
                args=[],
                keywords=[
                    ast.keyword(
                        arg="func",
                        value=ast.Name(
                            id=self._names.detection_func_name, ctx=ast.Load()
                        ),
                    )
                ],
            ),
        )

    def _enabled_keyword(self) -> ast.keyword:
        enabled = self._yaml_result.get("Enabled", False)
        return ast.keyword(arg="enabled", value=ast.Constant(value=enabled))

    def _log_types_keyword(self) -> ast.keyword:
        log_types = self._yaml_result["LogTypes"]
        val: Any
        if isinstance(log_types, str):
            val = ast.Constant(value=log_types)
        else:
            val = self._string_list_value(log_types)
        return ast.keyword(
            arg="log_types",
            value=val,
        )

    def _unit_tests_keyword(self) -> ast.keyword:
        if self._detection_type == "policy":
            data_key = "Resource"
        else:
            data_key = "Log"
        calls = []
        for unit_test in self._yaml_result.get("Tests", []):
            mock_calls = []
            for mock in unit_test.get("Mocks", []):
                mock_call = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="detection", ctx=ast.Load()),
                        attr="UnitTestMock",
                        ctx=ast.Load(),
                    ),
                    args=[],
                    keywords=[
                        ast.keyword(
                            arg="name",
                            value=ast.Constant(value=mock.get("objectName", "")),
                        ),
                        ast.keyword(
                            arg="return_value",
                            value=ast.Constant(value=mock.get("returnValue", "")),
                        ),
                    ],
                )
                mock_calls.append(mock_call)
            call = ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="detection", ctx=ast.Load()),
                    attr="JSONUnitTest",
                    ctx=ast.Load(),
                ),
                args=[],
                keywords=[
                    ast.keyword(
                        arg="data",
                        value=ast.Constant(
                            value=json.dumps(unit_test.get(data_key, ""))
                        ),
                    ),
                    ast.keyword(
                        arg="name", value=ast.Constant(value=unit_test.get("Name", ""))
                    ),
                    ast.keyword(
                        arg="expect_match",
                        value=ast.Constant(
                            value=unit_test.get("ExpectedResult", False)
                        ),
                    ),
                    ast.keyword(
                        arg="mocks", value=ast.List(elts=mock_calls, ctx=ast.Load())
                    ),
                ],
            )
            calls.append(call)
        return ast.keyword(
            arg="unit_tests",
            value=ast.List(
                elts=calls,
            ),
        )

    def _tags_keyword(self) -> ast.keyword:
        tags = self._yaml_result.get("Tags", [])
        val = self._string_list_value(tags)
        return ast.keyword(
            arg="tags",
            value=val,
        )

    def _reference_keyword(self) -> ast.keyword:
        reference = self._yaml_result.get("Reference", "")
        value: Any
        if self._names.reference_func_name is not None:
            value = self._dynamic_string_call_value(
                self._names.reference_func_name, reference
            )
        else:
            value = ast.Constant(value=reference)
        return ast.keyword(
            arg="reference",
            value=value,
        )

    def _runbook_keyword(self) -> ast.keyword:
        runbook = self._yaml_result.get("Runbook", "")
        value: Any
        if self._names.runbook_func_name is not None:
            value = self._dynamic_string_call_value(
                self._names.runbook_func_name, runbook
            )
        else:
            value = ast.Constant(value=runbook)
        return ast.keyword(
            arg="runbook",
            value=value,
        )

    def _description_keyword(self) -> ast.keyword:
        description = self._yaml_result.get("Description", "")
        value: Any
        if self._names.description_func_name is not None:
            value = self._dynamic_string_call_value(
                self._names.description_func_name, description
            )
        else:
            value = ast.Constant(value=description)
        return ast.keyword(
            arg="description",
            value=value,
        )

    def _summary_attrs_keyword(self) -> ast.keyword:
        attrs = self._yaml_result.get("SummaryAttributes", [])
        val = self._string_list_value(attrs)
        return ast.keyword(
            arg="summary_attrs",
            value=val,
        )

    def _reports_keyword(self) -> ast.keyword:
        reports = self._yaml_result.get("Reports", {})
        keys = []
        values = []
        for k, v in reports.items():
            keys.append(ast.Constant(value=k))
            values.append(self._string_list_value(v))
        return ast.keyword(
            arg="reports",
            value=ast.Dict(
                keys=keys,
                values=values,
            ),
        )

    def _alert_title_keyword(self) -> ast.keyword:
        val: Any
        if self._names.title_func_name is not None:
            val = ast.Name(id=self._names.title_func_name, ctx=ast.Load())
        else:
            val = ast.Constant(value=None)
        return ast.keyword(
            arg="alert_title",
            value=val,
        )

    def _alert_context_keyword(self) -> ast.keyword:
        val: Any
        if self._names.alert_context_func_name is not None:
            val = ast.Name(id=self._names.alert_context_func_name, ctx=ast.Load())
        else:
            val = ast.Constant(value=None)
        return ast.keyword(
            arg="alert_context",
            value=val,
        )

    def _destinations_keyword(self) -> ast.keyword:
        destinations = self._yaml_result.get("Destinations", None)
        val: Any
        if self._names.destinations_func_name is not None:
            val = self._dynamic_destinations_call_value(
                self._names.destinations_func_name, destinations
            )
        else:
            val = ast.Constant(value=None)
        return ast.keyword(
            arg="destinations",
            value=val,
        )

    def _alert_grouping_keyword(self) -> ast.keyword:
        dedup_period_minutes = self._yaml_result.get("DedupPeriodMinutes", 15)
        val = self._alert_grouping_call_value(
            period_minutes=dedup_period_minutes,
            group_by=self._names.dedup_func_name,
        )
        return ast.keyword(
            arg="alert_grouping",
            value=val,
        )

    def _resource_types_keyword(self) -> ast.keyword:
        resource_types = self._yaml_result["ResourceTypes"]
        val: Any
        if isinstance(resource_types, str):
            val = ast.Constant(value=resource_types)
        else:
            val = self._string_list_value(resource_types)
        return ast.keyword(
            arg="resource_types",
            value=val,
        )

    def _ignore_patterns_keyword(self) -> ast.keyword:
        suppressions = self._yaml_result.get("Suppressions", None)
        val: Any
        if suppressions is None or isinstance(suppressions, str):
            val = ast.Constant(value=suppressions)
        else:
            val = self._string_list_value(suppressions)
        return ast.keyword(
            arg="ignore_patterns",
            value=val,
        )

    def _scheduled_queries_keyword(self) -> ast.keyword:
        queries = self._yaml_result.get("ScheduledQueries", [])
        val = self._string_list_value(queries)
        return ast.keyword(
            arg="scheduled_queries",
            value=val,
        )

    def _sql_keyword(self) -> ast.keyword:
        if self._is_athena:
            sql = self._yaml_result.get("AthenaQuery", "")
        else:
            sql = self._yaml_result.get("SnowflakeQuery", "")
        return ast.keyword(
            arg="sql",
            value=ast.Constant(value=sql),
        )

    def _schedule_keyword(self) -> ast.keyword:
        schedule = self._yaml_result.get("Schedule", "")
        if "CronExpression" in schedule:
            val = self._cron_schedule_call_value(
                expression=schedule.get("CronExpression", ""),
                timeout_minutes=schedule.get("TimeoutMinutes", 0),
            )
        else:
            val = self._interval_schedule_call_value(
                rate_minutes=schedule.get("RateMinutes", 0),
                timeout_minutes=schedule.get("TimeoutMinutes", 0),
            )
        return ast.keyword(
            arg="schedule",
            value=val,
        )

    def _dynamic_string_call_value(self, func_name: str, fallback: str) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="DynamicStringField",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(arg="func", value=ast.Name(id=func_name, ctx=ast.Load())),
                ast.keyword(arg="fallback", value=ast.Constant(value=fallback)),
            ],
        )

    def _dynamic_destinations_call_value(
        self, func_name: str, fallback: str
    ) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="DynamicDestinationsField",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(arg="func", value=ast.Name(id=func_name, ctx=ast.Load())),
                ast.keyword(arg="fallback", value=ast.Constant(value=fallback)),
            ],
        )

    def _alert_grouping_call_value(
        self, period_minutes: int, group_by: Optional[str]
    ) -> ast.Call:
        if group_by is None:
            group_by_keyword = ast.keyword(
                arg="group_by", value=ast.Constant(value=None)
            )
        else:
            group_by_keyword = ast.keyword(
                arg="group_by", value=ast.Name(id=group_by, ctx=ast.Load())
            )
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="AlertGrouping",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(
                    arg="period_minutes", value=ast.Constant(value=period_minutes)
                ),
                group_by_keyword,
            ],
        )

    def _cron_schedule_call_value(
        self, expression: str, timeout_minutes: int
    ) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="CronSchedule",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(
                    arg="expression", value=ast.Name(id=expression, ctx=ast.Load())
                ),
                ast.keyword(
                    arg="timeout_minutes", value=ast.Constant(value=timeout_minutes)
                ),
            ],
        )

    def _interval_schedule_call_value(
        self, rate_minutes: int, timeout_minutes: int
    ) -> ast.Call:
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="detection", ctx=ast.Load()),
                attr="IntervalSchedule",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[
                ast.keyword(
                    arg="rate_minutes", value=ast.Name(id=rate_minutes, ctx=ast.Load())
                ),
                ast.keyword(
                    arg="timeout_minutes", value=ast.Constant(value=timeout_minutes)
                ),
            ],
        )

    def _string_list_value(self, string_list: list) -> ast.List:
        elts = []
        for s in string_list:
            elts.append(
                ast.Constant(
                    value=s,
                )
            )
        return ast.List(
            elts=elts,
            ctx=ast.Load(),
        )


def severity_to_enum(severity: str) -> str:
    return {
        "info": detection.SeverityInfo,
        "low": detection.SeverityLow,
        "medium": detection.SeverityMedium,
        "high": detection.SeverityHigh,
        "critical": detection.SeverityCritical,
    }.get(severity.lower(), detection.SeverityInfo)
