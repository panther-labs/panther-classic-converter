# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast
from typing import List


def fix_imports(tree: ast.AST) -> None:
    import_parser = ImportVisitor()
    import_parser.visit(tree)
    import_fixer = ImportFixer(import_parser.get_import_nodes())
    import_fixer.visit(tree)


class ImportFixer(ast.NodeTransformer):
    def __init__(self, imports_nodes: List):
        self._import_nodes = imports_nodes

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        for n in self._import_nodes:
            node.body.insert(0, n)
        return node

    # add the panther_sdk imports to the top level
    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body.insert(0, detection_import_from_node())
        self.generic_visit(node)
        return node


class ImportVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self._import_nodes: List[ast.AST] = []

    def visit_Import(self, node: ast.Import) -> None:
        self._import_nodes.append(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._import_nodes.append(node)

    def get_import_nodes(self) -> list:
        return self._import_nodes


def detection_import_from_node() -> ast.ImportFrom:
    return ast.ImportFrom(
        level=0,
        module="panther_sdk",
        names=[ast.alias(name="detection"), ast.alias(name="PantherEvent")],
    )
