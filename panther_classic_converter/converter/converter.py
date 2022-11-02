# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast
import os

import yaml
import black
import autoflake

from .import_fixer import fix_imports
from .detection_builder import append_detection
from .linter_fixer import fix_type_hints
from .name_fixer import fix_names


def convert_detection(yml_filename: str, is_athena: bool) -> str:

    with open(yml_filename, "r") as file:
        y = yaml.safe_load(file)
    if "Filename" in y:
        py_path = os.path.join(os.path.dirname(yml_filename), y["Filename"])
        with open(py_path, "r") as file:
            tree = ast.parse(file.read())
    else:
        tree = empty_tree()

    fix_imports(tree)
    fix_type_hints(tree)
    name_changes = fix_names(tree, get_id(y))
    append_detection(tree, y, name_changes, is_athena)
    unparsed = ast.unparse(tree)
    unparsed = prepend_nolint(unparsed)

    # remove unused imports
    unparsed = autoflake.fix_code(
        unparsed,
        remove_all_unused_imports=True,
    )

    # make pretty
    return black.format_str(unparsed, mode=black.FileMode())


def get_id(yaml_config: dict) -> str:
    analysis_type = yaml_config["AnalysisType"]
    if analysis_type == "rule" or analysis_type == "scheduled_rule":
        return yaml_config["RuleID"]
    if analysis_type == "policy":
        return yaml_config["PolicyID"]
    return ""


def empty_tree() -> ast.Module:
    return ast.fix_missing_locations(ast.Module(body=[], type_ignores=[]))


def prepend_nolint(body: str) -> str:
    return f"#nolint\n{body}"
