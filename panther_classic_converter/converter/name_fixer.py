# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast
import re


class UpdatedFunctionNames(object):
    detection_func_name = None
    title_func_name = None
    dedup_func_name = None
    alert_context_func_name = None
    severity_func_name = None
    description_func_name = None
    reference_func_name = None
    runbook_func_name = None
    destinations_func_name = None


def fix_names(tree: ast.AST, detection_id) -> UpdatedFunctionNames:
    name_fixer = NameFixer(detection_id)
    name_fixer.visit(tree)
    return name_fixer.get_updated_function_names()


class NameFixer(ast.NodeTransformer):
    def __init__(self, id: str):
        self._prefix = self._id_to_prefix(id)
        self._results = UpdatedFunctionNames()

    def get_updated_function_names(self) -> UpdatedFunctionNames:
        return self._results

    def _prefix_name(self, og: str) -> str:
        return f'_{self._prefix}_{og}'

    def _id_to_prefix(self, id: str) -> str:
        return re.sub('[^a-zA-Z0-9]', '_', id).lower()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name == "rule" or node.name == "policy":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.detection_func_name = new_name

        if node.name == "title":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.title_func_name = new_name

        if node.name == "dedup":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.dedup_func_name = new_name

        if node.name == "alert_context":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.alert_context_func_name = new_name

        if node.name == "severity":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.severity_func_name = new_name

        if node.name == "description":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.description_func_name = new_name

        if node.name == "reference":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.reference_func_name = new_name

        if node.name == "runbook":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.runbook_func_name = new_name

        if node.name == "destinations":
            new_name = self._prefix_name(node.name)
            node.name = new_name
            self._results.destinations_func_name = new_name
        return node

