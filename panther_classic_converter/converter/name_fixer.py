# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast
import re
from typing import Optional


class UpdatedFunctionNames(object):
    detection_func_name: Optional[str] = None
    title_func_name: Optional[str] = None
    dedup_func_name: Optional[str] = None
    alert_context_func_name: Optional[str] = None
    severity_func_name: Optional[str] = None
    description_func_name: Optional[str] = None
    reference_func_name: Optional[str] = None
    runbook_func_name: Optional[str] = None
    destinations_func_name: Optional[str] = None


def fix_names(tree: ast.AST, detection_id: str) -> UpdatedFunctionNames:
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        new_name = self._prefix_name(node.name)
        node.name = new_name
        if node.name == "rule" or node.name == "policy":
            self._results.detection_func_name = new_name

        if node.name == "title":
            self._results.title_func_name = new_name

        if node.name == "dedup":
            self._results.dedup_func_name = new_name

        if node.name == "alert_context":
            self._results.alert_context_func_name = new_name

        if node.name == "severity":
            self._results.severity_func_name = new_name

        if node.name == "description":
            self._results.description_func_name = new_name

        if node.name == "reference":
            self._results.reference_func_name = new_name

        if node.name == "runbook":
            self._results.runbook_func_name = new_name

        if node.name == "destinations":
            self._results.destinations_func_name = new_name
        return node

