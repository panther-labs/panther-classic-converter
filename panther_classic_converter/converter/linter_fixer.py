# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import ast


def fix_type_hints(tree: ast.AST):
    type_hint_fixer = TypeHintFixer()
    type_hint_fixer.visit(tree)


class TypeHintFixer(ast.NodeTransformer):
    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name == "rule" or node.name == "policy":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='bool', ctx=ast.Load())

        if node.name == "title":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "dedup":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "alert_context":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='dict', ctx=ast.Load())

        if node.name == "severity":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "description":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "reference":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "runbook":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Name(id='str', ctx=ast.Load())

        if node.name == "destinations":
            node.args.args[0].annotation = ast.Name(id='PantherEvent', ctx=ast.Load())
            node.returns = ast.Subscript(
                value=ast.Name(id='list', ctx=ast.Load()),
                slice=ast.Name(id='str', ctx=ast.Load()),
                ctx=ast.Load()
            )
        return node