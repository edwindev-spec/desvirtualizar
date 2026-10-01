"""Static lifting of the numeric dispatcher emitted by Prometheus Vmify.

Optional dependency: luaparser==4.2.0. No input is executed by the Lua runtime.
The restricted evaluator handles only the constant-array initialization prefix.
"""
from __future__ import annotations

import copy
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path

from luaparser import ast, astnodes as N


class Unsupported(ValueError):
    pass



def parse_lua(source):
    """Use ANTLR's fast SLL pass, falling back to the normal parser on ambiguity."""
    from antlr4.atn.PredictionMode import PredictionMode
    lexer = ast.LuaLexer(ast.InputStream(source))
    lexer.removeErrorListeners()
    lexer.addErrorListener(ast.BailErrorListener())
    stream = ast.CommonTokenStream(lexer, channel=ast.Token.DEFAULT_CHANNEL)
    parser = ast.LuaParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(ast.BailErrorListener())
    parser._errHandler = ast.BailErrorStrategy()
    parser._interp.predictionMode = PredictionMode.SLL
    try:
        tree = parser.start_()
    except ast.ParseCancellationException:
        result = ast.parse(source)
    else:
        result = ast.BuilderVisitor(stream).visit(tree)
    # luaparser converts decimal escapes through Unicode, corrupting bytes >127.
    # Decode the original token with our byte-preserving Lua lexer instead.
    from prometheus_devirt_100 import tokenize
    for node in walk(result):
        if isinstance(node, N.String) and node._first_token is not None:
            raw = node._first_token.text.encode('latin1')
            tokens = list(tokenize(raw))
            if len(tokens) != 1 or tokens[0].kind != 'string':
                raise Unsupported('cannot preserve original string bytes')
            node.s = tokens[0].value
    # Token objects retain the lexer and its DFA; copying them with every VM
    # function needlessly duplicates parser state. They have no emitted meaning.
    for node in walk(result):
        node._first_token = node._last_token = None
        node.comments = []
    return result


class LiftedExpression(N.Node):
    """Already emitted, trusted Lua expression; never reparse generated code."""
    def __init__(self, source):
        super().__init__('LiftedExpression')
        self.source = source

def fields(node):
    if isinstance(node, N.Node):
        for key, value in vars(node).items():
            if not key.startswith('_') and key not in ('comments', 'wrapped'):
                yield key, value


def walk(node):
    if isinstance(node, N.Node):
        yield node
        for _, value in fields(node):
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def transform(node, fn):
    if isinstance(node, list):
        return [transform(x, fn) for x in node]
    if not isinstance(node, N.Node):
        return node
    for key, value in list(fields(node)):
        if isinstance(value, (N.Node, list)):
            setattr(node, key, transform(value, fn))
    return fn(node)


OPS = {'AddOp': '+', 'SubOp': '-', 'MultOp': '*', 'FloatDivOp': '/',
       'FloorDivOp': '//', 'ModOp': '%', 'ExpoOp': '^', 'Concat': '..',
       'AndLoOp': 'and', 'OrLoOp': 'or', 'LessThanOp': '<', 'GreaterThanOp': '>',
       'LessOrEqThanOp': '<=', 'GreaterOrEqThanOp': '>=', 'EqToOp': '==', 'NotEqToOp': '~='}
UNARY = {'UMinusOp': '-', 'ULNotOp': 'not ', 'ULengthOP': '#'}


def literal(value):
    if value is None:
        return N.Nil()
    if isinstance(value, bool):
        return N.TrueExpr() if value else N.FalseExpr()
    if isinstance(value, (int, float)):
        return N.Number(value)
    if isinstance(value, bytes):
        return N.String(value, raw="")
    raise Unsupported('non-scalar literal')


def quote(value):
    return '"' + ''.join(chr(b) if 32 <= b < 127 and b not in (34, 92) else '\\%03d' % b for b in value) + '"'


def emit(node, level=0):
    """Parenthesize every expression; preserve bytes and multiple-return rules."""
    if node is None:
        return ''
    if isinstance(node, list):
        return ', '.join(emit(x) for x in node)
    if isinstance(node, LiftedExpression):
        return node.source
    cls = type(node).__name__
    if cls in OPS:
        return '(' + emit(node.left) + ' ' + OPS[cls] + ' ' + emit(node.right) + ')'
    if cls in UNARY:
        return '(' + UNARY[cls] + emit(node.operand) + ')'
    if isinstance(node, N.Name):
        return node.id
    if isinstance(node, N.Number):
        if math.isinf(node.n):
            return '(-1e999)' if node.n < 0 else '1e999'
        if math.isnan(node.n):
            return '(0/0)'
        return str(node.n) if node.n >= 0 else '(' + str(node.n) + ')'
    if isinstance(node, N.String):
        return quote(node.s)
    if isinstance(node, N.Nil):
        return 'nil'
    if isinstance(node, N.TrueExpr):
        return 'true'
    if isinstance(node, N.FalseExpr):
        return 'false'
    if isinstance(node, (N.Varargs, N.Dots)):
        return '(...)' if node.wrapped else '...'
    if isinstance(node, N.Index):
        base = emit(node.value)
        if not isinstance(node.value, (N.Name, N.Index, N.Call, N.Invoke, N.AnonymousFunction)):
            base = '(' + base + ')'
        return base + '[' + emit(node.idx) + ']'
    if isinstance(node, N.Table):
        return '{' + ', '.join(('[' + emit(f.key) + '] = ' if f.key is not None else '') + emit(f.value) for f in node.fields) + '}'
    if isinstance(node, N.Call):
        result = emit(node.func) + '(' + emit(node.args) + ')'
        return '(' + result + ')' if node.wrapped else result
    if isinstance(node, N.Invoke):
        result = emit(node.source) + ':' + emit(node.func) + '(' + emit(node.args) + ')'
        return '(' + result + ')' if node.wrapped else result
    if isinstance(node, N.AnonymousFunction):
        return '(function(' + emit(node.args) + ')\n' + indent(emit(node.body)) + '\nend)'
    if isinstance(node, N.LocalFunction):
        return 'local function ' + emit(node.name) + '(' + emit(node.args) + ')\n' + indent(emit(node.body)) + '\nend'
    if isinstance(node, N.Function):
        return emit(node.name) + ' = (function(' + emit(node.args) + ')\n' + indent(emit(node.body)) + '\nend)'
    if isinstance(node, N.Method):
        target = emit(node.source) + '[' + quote(node.name.id.encode('latin1')) + ']'
        return target + ' = (function(' + emit([N.Name('self'), *node.args]) + ')\n' + indent(emit(node.body)) + '\nend)'
    if isinstance(node, N.LocalAssign):
        return 'local ' + emit(node.targets) + (' = ' + emit(node.values) if node.values else '')
    if isinstance(node, N.Assign):
        return emit(node.targets) + ' = ' + emit(node.values)
    if isinstance(node, N.Return):
        return 'return ' + emit(node.values)
    if isinstance(node, (N.If, N.ElseIf)):
        result = 'if ' + emit(node.test) + ' then\n' + indent(emit(node.body))
        if node.orelse and not (isinstance(node.orelse, N.Block) and not node.orelse.body):
            result += '\nelse\n' + indent(emit(node.orelse))
        return result + '\nend'
    if isinstance(node, N.While):
        return 'while ' + emit(node.test) + ' do\n' + indent(emit(node.body)) + '\nend'
    if isinstance(node, N.Fornum):
        step = emit(node.step) if isinstance(node.step, N.Node) else str(node.step)
        return 'for ' + emit(node.target) + ' = ' + emit(node.start) + ', ' + emit(node.stop) + ', ' + step + ' do\n' + indent(emit(node.body)) + '\nend'
    if isinstance(node, N.Forin):
        return 'for ' + emit(node.targets) + ' in ' + emit(node.iter) + ' do\n' + indent(emit(node.body)) + '\nend'
    if isinstance(node, N.Do):
        return 'do\n' + indent(emit(node.body)) + '\nend'
    if isinstance(node, N.Repeat):
        return 'repeat\n' + indent(emit(node.body)) + '\nuntil ' + emit(node.test)
    if isinstance(node, N.Goto):
        return 'goto ' + emit(node.label)
    if isinstance(node, N.Label):
        return '::' + emit(node.id) + '::'
    if isinstance(node, N.Break):
        return 'break'
    if isinstance(node, N.SemiColon):
        return ';'
    if isinstance(node, N.Block):
        return '\n'.join(emit(s) for s in node.body)
    if isinstance(node, N.Chunk):
        return emit(node.body)
    raise Unsupported('cannot emit ' + cls)


def indent(text):
    return '\n'.join('  ' + line for line in text.splitlines())


def truth(value):
    return value is not None and value is not False


def arithmetic(cls, a, b=None):
    if cls == 'AddOp': return a + b
    if cls == 'SubOp': return a - b
    if cls == 'MultOp': return a * b
    if cls == 'FloatDivOp': return a / b
    if cls == 'FloorDivOp': return a // b
    if cls == 'ModOp': return a % b
    if cls == 'ExpoOp': return a ** b
    if cls == 'LessThanOp': return a < b
    if cls == 'GreaterThanOp': return a > b
    if cls == 'LessOrEqThanOp': return a <= b
    if cls == 'GreaterOrEqThanOp': return a >= b
    if cls == 'EqToOp': return a == b
    if cls == 'NotEqToOp': return a != b
    if cls == 'Concat': return a + b
    if cls == 'UMinusOp': return -a
    if cls == 'ULNotOp': return not truth(a)
    if cls == 'ULengthOP': return len(a)
    raise Unsupported('operator ' + cls)


def fold(node):
    cls = type(node).__name__
    if cls in ('AddOp', 'SubOp', 'MultOp', 'FloatDivOp', 'ModOp', 'ExpoOp') and isinstance(node.left, N.Number) and isinstance(node.right, N.Number):
        a, b = node.left.n, node.right.n
        if not all(math.isfinite(x) and abs(x) <= 2**53 for x in (a, b)):
            return node
        if cls == 'ExpoOp' and abs(b) > 64:
            return node
        try:
            result = arithmetic(cls, a, b)
            if math.isfinite(result) and abs(result) <= 2**53:
                return N.Number(result)
        except (ArithmeticError, ValueError, TypeError):
            pass
    if isinstance(node, N.UMinusOp) and isinstance(node.operand, N.Number):
        return N.Number(-node.operand.n)
    return node


class Scope:
    def __init__(self, parent=None):
        self.values, self.parent = {}, parent

    def get(self, name):
        if name in self.values: return self.values[name]
        if self.parent: return self.parent.get(name)
        raise Unsupported('unknown name in constant prefix: ' + name)

    def set(self, name, value):
        if name in self.values: self.values[name] = value
        elif self.parent: self.parent.set(name, value)
        else: raise Unsupported('global write in constant prefix: ' + name)


class LoopBreak(Exception):
    pass


class Returned(Exception):
    def __init__(self, values): self.values = values


class ConstantEvaluator:
    """Restricted Lua subset; budgeted, no io, OS, load or network APIs."""
    def __init__(self, limit=200000):
        self.limit = limit
        self.scope = Scope()
        def sub(s, a, b=None):
            if not isinstance(a, (int, float)) or a != int(a) or b is not None and (not isinstance(b, (int, float)) or b != int(b)):
                raise Unsupported('non-integer constant string index')
            a, b = int(a), int(b) if b is not None else None
            a = len(s) + a + 1 if a < 0 else a
            b = len(s) if b is None else len(s) + b + 1 if b < 0 else b
            return s[max(a - 1, 0):max(b, 0)]
        def insert(t, value): t[len(t) + 1] = value
        def lua_type(x):
            return b'string' if isinstance(x, bytes) else b'table' if isinstance(x, dict) else b'number' if isinstance(x, (int, float)) else b'nil' if x is None else b'function'
        self.scope.values.update({
            'math': {b'floor': math.floor},
            'string': {b'len': len, b'sub': sub, b'char': lambda *v: bytes(int(x) for x in v)},
            'table': {b'insert': insert, b'concat': lambda t: b''.join(t[i] for i in range(1, len(t) + 1))},
            'type': lua_type, 'ipairs': lambda t: [(i, t[i]) for i in range(1, len(t) + 1)]})

    def tick(self):
        self.limit -= 1
        if self.limit < 0: raise Unsupported('constant-prefix evaluation budget exceeded')

    def expr(self, node, scope):
        self.tick()
        if isinstance(node, N.Name): return scope.get(node.id)
        if isinstance(node, N.Number): return node.n
        if isinstance(node, N.String): return node.s
        if isinstance(node, N.Nil): return None
        if isinstance(node, N.TrueExpr): return True
        if isinstance(node, N.FalseExpr): return False
        if isinstance(node, N.Table):
            table, index = {}, 1
            for f in node.fields:
                key = self.expr(f.key, scope) if f.key is not None else index
                if f.key is None: index += 1
                table[key] = self.expr(f.value, scope)
            return table
        if isinstance(node, N.Index): return self.expr(node.value, scope).get(self.expr(node.idx, scope))
        if isinstance(node, N.AndLoOp):
            a = self.expr(node.left, scope)
            return self.expr(node.right, scope) if truth(a) else a
        if isinstance(node, N.OrLoOp):
            a = self.expr(node.left, scope)
            return a if truth(a) else self.expr(node.right, scope)
        if type(node).__name__ in OPS:
            return arithmetic(type(node).__name__, self.expr(node.left, scope), self.expr(node.right, scope))
        if type(node).__name__ in UNARY:
            return arithmetic(type(node).__name__, self.expr(node.operand, scope))
        if isinstance(node, N.Call):
            func = self.expr(node.func, scope)
            if not callable(func): raise Unsupported('non-callable in constant prefix')
            return func(*[self.expr(a, scope) for a in node.args])
        raise Unsupported('constant expression: ' + type(node).__name__)

    def run(self, block, scope=None):
        scope = scope or self.scope
        for stmt in block.body:
            self.tick()
            if isinstance(stmt, N.LocalFunction):
                def func(*args, fn=stmt, closure=scope):
                    local = Scope(closure)
                    local.values.update((a.id, v) for a, v in zip(fn.args, args))
                    try: self.run(fn.body, local)
                    except Returned as ret:
                        if len(ret.values) == 1: return ret.values[0]
                        raise Unsupported('multi-return constant function')
                scope.values[stmt.name.id] = func
            elif isinstance(stmt, N.Assign):
                values = [self.expr(v, scope) for v in stmt.values]
                targets = []
                for target in stmt.targets:
                    targets.append((self.expr(target.value, scope), self.expr(target.idx, scope)) if isinstance(target, N.Index) else (None, target.id))
                for idx, (table, key) in enumerate(targets):
                    value = values[idx] if idx < len(values) else None
                    if table is not None: table[key] = value
                    elif isinstance(stmt, N.LocalAssign): scope.values[key] = value
                    else: scope.set(key, value)
            elif isinstance(stmt, N.Forin):
                if len(stmt.iter) != 1: raise Unsupported('constant for-in')
                for values in self.expr(stmt.iter[0], scope):
                    local = Scope(scope)
                    local.values.update((a.id, v) for a, v in zip(stmt.targets, values))
                    self.run(stmt.body, local)
            elif isinstance(stmt, N.Fornum):
                start, stop = self.expr(stmt.start, scope), self.expr(stmt.stop, scope)
                step = self.expr(stmt.step, scope) if isinstance(stmt.step, N.Node) else stmt.step
                if not all(isinstance(v, (int, float)) and math.isfinite(v) and v == int(v) for v in (start, stop, step)) or step == 0: raise Unsupported('constant for range')
                start, stop, step = int(start), int(stop), int(step)
                for value in range(start, stop + (1 if step > 0 else -1), step):
                    local = Scope(scope); local.values[stmt.target.id] = value
                    self.run(stmt.body, local)
            elif isinstance(stmt, N.While):
                while truth(self.expr(stmt.test, scope)):
                    try: self.run(stmt.body, Scope(scope))
                    except LoopBreak: break
            elif isinstance(stmt, (N.If, N.ElseIf)):
                if truth(self.expr(stmt.test, scope)): self.run(stmt.body, Scope(scope))
                elif isinstance(stmt.orelse, N.Block): self.run(stmt.orelse, Scope(scope))
                elif stmt.orelse: self.run(N.Block([stmt.orelse]), Scope(scope))
            elif isinstance(stmt, N.Do): self.run(stmt.body, Scope(scope))
            elif isinstance(stmt, N.Call): self.expr(stmt, scope)
            elif isinstance(stmt, N.Return): raise Returned([self.expr(v, scope) for v in stmt.values])
            elif isinstance(stmt, N.Break): raise LoopBreak()
            elif not isinstance(stmt, N.SemiColon): raise Unsupported('constant statement: ' + type(stmt).__name__)


UNKNOWN = ('unknown', None)
UNKNOWN_TRUE = ('truthy', None)
NIL = ('nil', None)
FALSE = ('bool', False)
TRUE = ('bool', True)


def abstract(node, env):
    if isinstance(node, N.Number): return {('number', node.n)}
    if isinstance(node, N.String): return {('string', node.s)}
    if isinstance(node, N.Nil): return {NIL}
    if isinstance(node, N.TrueExpr): return {TRUE}
    if isinstance(node, N.FalseExpr): return {FALSE}
    if isinstance(node, N.Name): return env.get(node.id, {UNKNOWN})
    if isinstance(node, (N.AndLoOp, N.OrLoOp)):
        left, right, result = abstract(node.left, env), abstract(node.right, env), set()
        if UNKNOWN in left:
            left = (left - {UNKNOWN}) | {NIL, FALSE, UNKNOWN_TRUE}
        for value in left:
            is_true = value not in (NIL, FALSE)
            if isinstance(node, N.AndLoOp): result |= right if is_true else {value}
            else: result |= {value} if is_true else right
        return result
    if isinstance(node, (N.EqToOp, N.NotEqToOp, N.LessThanOp, N.GreaterThanOp,
                         N.LessOrEqThanOp, N.GreaterOrEqThanOp)):
        left, right = abstract(node.left, env), abstract(node.right, env)
        if all(kind not in ('unknown', 'truthy') for kind, _ in left | right):
            answers = set()
            for a in left:
                for b in right:
                    if isinstance(node, (N.EqToOp, N.NotEqToOp)):
                        value = a == b
                        if isinstance(node, N.NotEqToOp): value = not value
                    elif a[0] == b[0] and a[0] in ('number', 'string'):
                        value = arithmetic(type(node).__name__, a[1], b[1])
                    else:
                        return {TRUE, FALSE}
                    answers.add(TRUE if value else FALSE)
            return answers
        return {TRUE, FALSE}
    if isinstance(node, N.ULNotOp):
        values = abstract(node.operand, env)
        if UNKNOWN in values: return {TRUE, FALSE}
        return {TRUE if value in (NIL, FALSE) else FALSE for value in values}
    return {UNKNOWN}


@dataclass
class BasicBlock:
    id: int
    low: int | None
    high: int | None
    body: object
    targets: tuple = ()
    terminal: bool = False
    terminal_key: bytes | None = None
    low_open: bool = False
    high_closed: bool = False


def split_dispatcher(loop, pc):
    """Partition thresholds, including reversed comparisons and elseif chains."""
    blocks = []
    def comparison(test):
        if not isinstance(test, (N.LessThanOp, N.LessOrEqThanOp, N.GreaterThanOp, N.GreaterOrEqThanOp)):
            return None
        if isinstance(test.left, N.Name) and test.left.id == pc and isinstance(test.right, N.Number):
            return type(test).__name__, test.right.n
        if isinstance(test.right, N.Name) and test.right.id == pc and isinstance(test.left, N.Number):
            inverse = {'LessThanOp': 'GreaterThanOp', 'LessOrEqThanOp': 'GreaterOrEqThanOp',
                       'GreaterThanOp': 'LessThanOp', 'GreaterOrEqThanOp': 'LessOrEqThanOp'}
            return inverse[type(test).__name__], test.left.n
        return None
    def intersect(bounds, low=None, high=None, low_open=False, high_closed=False):
        lo, hi, opened, closed = bounds
        if low is not None and (lo is None or low > lo): lo, opened = low, low_open
        elif low is not None and low == lo: opened = opened or low_open
        if high is not None and (hi is None or high < hi): hi, closed = high, high_closed
        elif high is not None and high == hi: closed = closed and high_closed
        if lo is not None and hi is not None and (lo > hi or lo == hi and (opened or not closed)):
            raise Unsupported('empty or non-monotonic dispatcher range')
        return lo, hi, opened, closed
    def visit(body, bounds):
        branch = body if isinstance(body, N.ElseIf) else body.body[0] if len(body.body) == 1 and isinstance(body.body[0], N.If) else None
        test = comparison(branch.test) if branch is not None else None
        if test:
            operator, pivot = test
            if branch.orelse is None:
                raise Unsupported('dispatcher has no default leaf')
            less = operator in ('LessThanOp', 'LessOrEqThanOp')
            inclusive = operator in ('LessOrEqThanOp', 'GreaterOrEqThanOp')
            below = intersect(bounds, high=pivot, high_closed=inclusive if less else not inclusive)
            above = intersect(bounds, low=pivot, low_open=not inclusive if not less else inclusive)
            visit(branch.body, below if less else above)
            visit(branch.orelse, above if less else below)
            return
        if isinstance(body, N.ElseIf):
            raise Unsupported('dispatcher elseif is not a numeric threshold')
        lo, hi, opened, closed = bounds
        blocks.append(BasicBlock(len(blocks), lo, hi, body, low_open=opened, high_closed=closed))
    visit(loop.body, (None, None, False, False))
    if not blocks or len(blocks) == 1 and not any(
            isinstance(s, N.Assign) and any(isinstance(t, N.Name) and t.id == pc for t in s.targets)
            for s in blocks[0].body.body):
        raise Unsupported('numeric dispatcher not found')
    return blocks


def resolve_edges(blocks, pc, environment):
    def locate(state):
        matches = [b.id for b in blocks if (b.low is None or state > b.low or state == b.low and not b.low_open) and (b.high is None or state < b.high or state == b.high and b.high_closed)]
        if len(matches) != 1: raise Unsupported('ambiguous state ' + str(state))
        return matches[0]
    for block in blocks:
        env, last_pc = {}, None
        for stmt in block.body.body:
            if not isinstance(stmt, (N.Assign, N.Call, N.Invoke, N.SemiColon)):
                raise Unsupported('nested control flow inside VM leaf')
            if isinstance(stmt, N.Assign):
                values = [abstract(v, env) for v in stmt.values]
                for i, target in enumerate(stmt.targets):
                    if isinstance(target, N.Name):
                        expands = bool(stmt.values) and isinstance(stmt.values[-1], (N.Call, N.Invoke, N.Varargs, N.Dots)) and not stmt.values[-1].wrapped
                        env[target.id] = values[i] if i < len(values) else {UNKNOWN} if expands else {NIL}
                        if target.id == pc:
                            last_pc = stmt.values[i] if i < len(stmt.values) else N.Nil()
        outcomes = env.get(pc, {UNKNOWN})
        if all(kind == 'number' for kind, _ in outcomes):
            block.targets = tuple(sorted((value, locate(value)) for _, value in outcomes))
        elif outcomes <= {NIL, FALSE}:
            block.terminal = True
        elif (isinstance(last_pc, N.Index) and isinstance(last_pc.value, N.Name)
              and last_pc.value.id == environment and isinstance(last_pc.idx, N.String)):
            block.terminal = True
            block.terminal_key = last_pc.idx.s
        else:
            raise Unsupported('unresolved target in block %d: %s' % (block.id, emit(last_pc)))
    return locate


def reachable(blocks, start):
    seen, todo = set(), [start]
    while todo:
        current = todo.pop()
        if current in seen: continue
        seen.add(current)
        todo.extend(target for _, target in blocks[current].targets)
    return seen



def entry_label(value):
    if not isinstance(value, (int, float)) or not math.isfinite(value) or value != int(value) or abs(value) > 2**53:
        raise Unsupported('VM closure entry is not an exact integer')
    return 'entry_' + str(int(value))

def lift_dispatcher(inner, cut_grass=False, *, environment_name=None, native="recovered_functions", structured=False, remove_antitamper=False):
    if len(inner.body.body) != 2 or not isinstance(inner.body.body[0], N.Assign):
        raise Unsupported('VM initializer shape not supported')
    init = inner.body.body[0]
    candidates = []
    for target, value in zip(init.targets, init.values):
        if isinstance(value, N.AnonymousFunction) and value.args:
            pc = value.args[0].id
            loops = [s for s in value.body.body if isinstance(s, N.While) and isinstance(s.test, N.Name) and s.test.id == pc]
            if loops:
                try: blocks = split_dispatcher(loops[0], pc)
                except Unsupported: continue
                candidates.append((target.id, value, loops[0], blocks))
    if len(candidates) != 1: raise Unsupported('expected one Vmify dispatcher')
    dispatch_name, dispatch, loop, blocks = candidates[0]
    pc = dispatch.args[0].id
    environment = environment_name or inner.args[0].id
    locate = resolve_edges(blocks, pc, environment)
    factories = {}
    for target, value in zip(init.targets, init.values):
        if value is dispatch: continue
        calls = [n for n in walk(value) if isinstance(n, N.Call) and isinstance(n.func, N.Name) and n.func.id == dispatch_name]
        if calls:
            if len(calls) != 1 or not isinstance(value, N.AnonymousFunction): raise Unsupported('unknown closure factory')
            call = calls[0]
            if not isinstance(call.args[0], N.Name) or call.args[0].id != value.args[0].id:
                raise Unsupported('non-parameter function entry')
            factories[target.id] = (value, call)
    blocked = {a.id for a in dispatch.args if isinstance(a, N.Name)}
    for stmt in dispatch.body.body:
        if isinstance(stmt, N.LocalAssign): blocked.update(t.id for t in stmt.targets)
    factory_calls = []
    for node in walk(dispatch):
        if isinstance(node, N.Call) and isinstance(node.func, N.Name) and node.func.id in factories and node.func.id not in blocked:
            factory_calls.append(node)
    factory_calls.extend(n for n in walk(inner.body.body[1]) if isinstance(n, N.Call) and isinstance(n.func, N.Name) and n.func.id in factories)
    entries = set()
    for node in factory_calls:
        if not node.args or not isinstance(node.args[0], N.Number):
            raise Unsupported('dynamic function entry: ' + emit(node))
        entries.add(node.args[0].n)
    if not entries: raise Unsupported('no function entries')
    bypass = None
    if remove_antitamper:
        main_calls = [n for n in walk(inner.body.body[1]) if isinstance(n, N.Call) and isinstance(n.func, N.Name) and n.func.id in factories]
        bypass = find_antitamper_boundary(blocks, entries, main_calls, locate)
        if bypass:
            _, guard_id, success_state, success_id = bypass
            guard = blocks[guard_id]
            for stmt in reversed(guard.body.body):
                if isinstance(stmt, N.Assign):
                    positions = [i for i, target in enumerate(stmt.targets) if isinstance(target, N.Name) and target.id == pc]
                    if positions:
                        position = positions[0]
                        if any(isinstance(n, (N.Call, N.Invoke)) for n in walk(stmt.values[position])):
                            raise Unsupported('antitamper guard has effectful condition')
                        stmt.values[position] = literal(success_state)
                        break
            else:
                raise Unsupported('antitamper guard has no explicit PC assignment')
            guard.targets = ((success_state, success_id),)
    if any(isinstance(n, N.Name) and n.id == native for n in walk(inner)):
        raise Unsupported('generated identifier collision')
    for node in factory_calls:
        node.args[0] = N.Index(literal(entry_label(node.args[0].n).encode()), N.Name(native), N.IndexNotation.SQUARE)
    for fn, call in factories.values():
        call.func, call.args = copy.deepcopy(call.args[0]), call.args[1:]
    init.values[init.values.index(dispatch)] = N.Nil()
    position = dispatch.body.body.index(loop)
    before, after = dispatch.body.body[:position], dispatch.body.body[position + 1:]
    if any(not isinstance(s, N.LocalAssign) for s in before): raise Unsupported('dispatcher has executable prelude')
    decoded = simplify_constants(blocks, decode=True) if cut_grass else []
    main_entry, main_start = (bypass[0], locate(bypass[0])) if bypass else (None, None)
    if cut_grass:
        main_entry, main_start = 5021362, 72
        entry_block = blocks[main_start]
        payload_start = next((i for i, stmt in enumerate(entry_block.body.body)
            if isinstance(stmt, N.Assign) and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], N.Name) and stmt.targets[0].id == 'l'
            and isinstance(stmt.values[0], N.Index) and emit(stmt.values[0]) == 'C["game"]'), None)
        if payload_start is None: raise Unsupported('CutGrass payload boundary not found')
        prefix = parse_lua('P = j(); Q = j(); k[P] = {}; k[Q] = nil').body.body
        tail = entry_block.body.body[payload_start:]
        tail = [stmt for stmt in tail if emit(stmt) != 'W = x(W)']
        entry_block.body.body = prefix + tail
        for block in blocks:
            if block.terminal_key:
                for stmt in reversed(block.body.body):
                    if isinstance(stmt, N.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], N.Name) and stmt.targets[0].id == pc:
                        stmt.values = [N.Nil()]
                        break
                block.terminal_key = None
        # Retain only native entries reachable through actual closure creation.
        selected, todo = set(), [main_entry]
        while todo:
            entry = todo.pop()
            if entry in selected: continue
            if entry not in entries: raise Unsupported('unknown native entry')
            selected.add(entry)
            start = main_start if entry == main_entry else locate(entry)
            for bid in reachable(blocks, start):
                for node in walk(blocks[bid].body):
                    if isinstance(node, N.Index) and isinstance(node.value, N.Name) and node.value.id == native and isinstance(node.idx, N.String):
                        todo.append(int(node.idx.s.removeprefix(b'entry_')))
        entries = selected
        registers = {pc} | {a.id for a in dispatch.args if isinstance(a, N.Name)}
        for stmt in before: registers.update(t.id for t in stmt.targets)
        simplify_branches(blocks, pc)
        trim_dead_registers(blocks, registers, after, pc)
    if bypass:
        selected, todo = set(), [main_entry]
        while todo:
            entry = todo.pop()
            if entry in selected: continue
            if entry not in entries: raise Unsupported('unrecognized function entry after antitamper')
            selected.add(entry)
            start = main_start if entry == main_entry else locate(entry)
            for bid in reachable(blocks, start):
                for node in walk(blocks[bid].body):
                    if isinstance(node, N.Index) and isinstance(node.value, N.Name) and node.value.id == native and isinstance(node.idx, N.String):
                        todo.append(int(node.idx.s.removeprefix(b'entry_')))
        entries = selected
    function_names = {entry: 'function_%02d' % i for i, entry in enumerate(sorted(entries), 1)}
    for node in walk([*[block.body for block in blocks], inner.body.body[1]]):
        if (isinstance(node, N.Index) and isinstance(node.value, N.Name) and node.value.id == native
                and isinstance(node.idx, N.String) and node.idx.s.startswith(b'entry_')):
            entry = int(node.idx.s.removeprefix(b'entry_'))
            if entry in function_names:
                node.idx = literal(function_names[entry].encode('ascii'))
    generated = ['local ' + native + ' = {}']
    function_records = []
    structured_failures = []
    for entry in sorted(entries):
        start = main_start if entry == main_entry else locate(entry)
        nodes = reachable(blocks, start)
        body = ['local ' + pc + ' = ' + str(entry), *[emit(s) for s in before], 'goto block_' + str(start)]
        for index in sorted(nodes):
            block = blocks[index]
            body.extend(['::block_' + str(index) + '::', 'do', indent(emit(block.body)), 'end'])
            if block.terminal:
                if block.terminal_key is not None:
                    body.append('if ' + pc + ' then error("unresolved dynamic Vmify exit", 0) end')
                body.append('goto function_return')
            elif len(block.targets) == 1:
                body.append('goto block_' + str(block.targets[0][1]))
            else:
                for offset, (state, target) in enumerate(block.targets):
                    if offset == len(block.targets) - 1:
                        body.append('else goto block_' + str(target) + ' end')
                    else:
                        body.append(('if' if offset == 0 else 'elseif') + ' ' + pc + ' == ' + str(state) + ' then goto block_' + str(target))
        body.extend(['::function_return::', *[emit(s) for s in after]])
        if cut_grass:
            body = ["local " + pc, *[emit(s) for s in before], structured_body(blocks, start, after)]
        elif structured:
            try:
                high_level = structured_body(blocks, start, after, pc=pc)
            except Unsupported as exc:
                structured_failures.append({'entry': entry, 'reason': str(exc)})
            else:
                body = ["local " + pc + " = " + str(entry), *[emit(s) for s in before], high_level]
        generated.append(native + '["' + function_names[entry] + '"] = function(' + emit(dispatch.args[1:]) + ')\n' + indent('\n'.join(body)) + '\nend')
        function_records.append({'entry': entry, 'name': function_names[entry], 'blocks': sorted(nodes)})
    generated.append(emit(init))
    generated.append(emit(inner.body.body[1]))
    source = '(function(' + emit(inner.args) + ')\n' + indent('\n'.join(generated)) + '\nend)'
    metadata = {'dispatcher_removed': True, 'vm_blocks': len(blocks), 'native_functions': len(entries), 'decoded_strings': decoded,
                'structured_fallbacks': structured_failures, 'antitamper_removed': cut_grass, 'antitamper_bypassed': bypass is not None, 'antitamper_boundary': bypass[1] if bypass else None, 'profile': 'CutGrassAdventure SHA-256' if cut_grass else None,
                'functions': function_records,
                'dynamic_exit_guards': sorted({b.terminal_key.decode('latin1') for b in blocks if b.terminal_key}),
                'unreachable_blocks': sorted(set(range(len(blocks))) - set().union(*(set(f['blocks']) for f in function_records)))}
    return source, metadata


CUT_GRASS_SHA256 = 'b9cca37758d9000081dd6ba04be0625900a29b418630f6b8d19924c95562843b'


def decrypt_cut_grass(cipher, seed):
    """Cipher parameters verified in the SHA-256 pinned input's PRNG blocks.

    The 45-bit product is below 2**53, so all integer operations are exact in
    the input's double-number model. The rotate follows its floating formula.
    """
    state45, state8, previous, pending = seed % 2**45, seed % 255 + 2, 113, []
    output = bytearray()
    for byte in cipher:
        if not pending:
            state45 = (state45 * 41 + 16026980965671) % 2**45
            while True:
                state8 = state8 * 87 % 257
                if state8 != 1: break
            rotation = state8 % 32
            fraction = (math.floor(state45 / 2**(13 - (state8 - rotation) // 32)) % 2**32) / 2**rotation
            word = math.floor((fraction % 1) * 2**32) + math.floor(fraction)
            pending = [(word >> shift) % 256 for shift in (0, 8, 16, 24)]
        previous = (byte + pending.pop() + previous) % 256
        output.append(previous)
    return bytes(output)


def simplify_constants(blocks, decode=False):
    pairs, reads = {}, 0
    for block in blocks:
        values = {}
        def replace(node):
            nonlocal reads
            if isinstance(node, N.Name) and node.id in values:
                return copy.deepcopy(values[node.id])
            if (decode and isinstance(node, N.Call) and len(node.args) == 2
                    and isinstance(node.args[0], N.String) and isinstance(node.args[1], N.Number)
                    and node.args[1].n > 2**32):
                cipher, seed = node.args[0].s, node.args[1].n
                plain = decrypt_cut_grass(cipher, seed)
                if seed in pairs and pairs[seed]['cipher_hex'] != cipher.hex():
                    raise Unsupported('cipher cache seed collision')
                pairs[seed] = {'seed': seed, 'cipher_hex': cipher.hex(), 'plain_hex': plain.hex()}
                replacement = N.Number(seed)
                replacement.decoded_value = plain
                return replacement
            if decode and isinstance(node, N.Index) and hasattr(node.idx, 'decoded_value'):
                reads += 1
                return literal(node.idx.decoded_value)
            return fold(node)
        for stmt in block.body.body:
            if isinstance(stmt, N.Assign):
                stmt.values = [transform(v, replace) for v in stmt.values]
                for target in stmt.targets:
                    if isinstance(target, N.Index):
                        target.idx = transform(target.idx, replace)
                        target.value = transform(target.value, replace)
                for i, target in enumerate(stmt.targets):
                    if isinstance(target, N.Name):
                        value = stmt.values[i] if i < len(stmt.values) else N.Nil()
                        if isinstance(value, (N.Number, N.String, N.TrueExpr, N.FalseExpr, N.Nil)):
                            values[target.id] = value
                        else: values.pop(target.id, None)
            elif isinstance(stmt, (N.Call, N.Invoke)):
                transform(stmt, replace)
    if decode and (len(pairs) != 187 or reads != 187):
        raise Unsupported('CutGrass cipher profile did not match all 187 lookups')
    return list(pairs.values())


def names_read(expr):
    return {n.id for n in walk(expr) if isinstance(n, N.Name)}


def trim_dead_registers(blocks, registers, after, pc):
    """Remove dead register copies/constants, retaining potentially effectful ops."""
    def uses_defs(stmt):
        if not isinstance(stmt, N.Assign): return names_read(stmt) & registers, set()
        defs = {t.id for t in stmt.targets if isinstance(t, N.Name)} & registers
        uses = names_read(stmt.values)
        for t in stmt.targets:
            if not isinstance(t, N.Name): uses |= names_read(t)
        return uses & registers, defs
    def disposable(value):
        if isinstance(value, (N.Number, N.String, N.TrueExpr, N.FalseExpr, N.Nil)): return True
        if isinstance(value, N.Name): return value.id in registers
        if isinstance(value, N.Index):
            root = value
            while isinstance(root, N.Index): root = root.value
            return isinstance(root, N.Name) and root.id in ('k', 'H', 'g') and all(
                isinstance(n, (N.Index, N.Name, N.Number, N.String)) for n in walk(value))
        return False
    while True:
        incoming, outgoing = {b.id: set() for b in blocks}, {}
        changed = True
        while changed:
            changed = False
            for block in reversed(blocks):
                live = set().union(*(incoming[target] for _, target in block.targets))
                if block.terminal: live |= names_read(after) & registers
                # Transition tests and guards are emitted outside the AST body.
                if block.terminal_key or len(block.targets) > 1: live.add(pc)
                outgoing[block.id] = live.copy()
                for stmt in reversed(block.body.body):
                    uses, defs = uses_defs(stmt)
                    live = (live - defs) | uses
                if live != incoming[block.id]: incoming[block.id] = live; changed = True
        removed = 0
        for block in blocks:
            live, body = outgoing[block.id], []
            for stmt in reversed(block.body.body):
                uses, defs = uses_defs(stmt)
                if (isinstance(stmt, N.Assign) and len(defs) == len(stmt.targets)
                        and not (defs & live) and all(disposable(v) for v in stmt.values)):
                    removed += 1
                    continue
                live = (live - defs) | uses
                body.append(stmt)
            block.body.body = list(reversed(body))
        if not removed: return


def simplify_branches(blocks, pc):
    for block in blocks:
        if len(block.targets) != 2: continue
        assignments = [(i, s) for i, s in enumerate(block.body.body) if isinstance(s, N.Assign)
                       and len(s.targets) == 1 and isinstance(s.targets[0], N.Name) and s.targets[0].id == pc]
        if not assignments: continue
        index, stmt = assignments[-1]
        rhs = stmt.values[0]
        conjunction = None
        if isinstance(rhs, N.OrLoOp) and isinstance(rhs.right, N.Number):
            if isinstance(rhs.left, N.AndLoOp): conjunction = rhs.left
            elif isinstance(rhs.left, N.Name) and rhs.left.id == pc and len(assignments) >= 2:
                prior, prior_stmt = assignments[-2]
                if isinstance(prior_stmt.values[0], N.AndLoOp) and not any(pc in names_read(s) for s in block.body.body[prior + 1:index]):
                    conjunction = prior_stmt.values[0]
                    block.body.body.pop(index)
                    index, stmt = prior, prior_stmt
        if conjunction is None or not isinstance(conjunction.right, N.Number): continue
        if any(pc in names_read(s) for s in block.body.body[index + 1:]): continue
        lookup = dict(block.targets)
        yes, no = conjunction.right.n, rhs.right.n
        if set(lookup) != {yes, no}: continue
        stmt.values = [N.ULNotOp(N.ULNotOp(conjunction.left))]
        block.condition = N.Name(pc)
        block.true_target, block.false_target = lookup[yes], lookup[no]


def natural_loops(blocks, start, nodes):
    predecessors = {node: set() for node in nodes}
    for node in nodes:
        for _, target in blocks[node].targets: predecessors[target].add(node)
    dominators = {node: ({node} if node == start else nodes.copy()) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in nodes - {start}:
            value = {node} | set.intersection(*(dominators[p] for p in predecessors[node]))
            if value != dominators[node]: dominators[node] = value; changed = True
    loops = {}
    for node in nodes:
        for _, header in blocks[node].targets:
            if header not in dominators[node]: continue
            members, todo = {header, node}, [node] if node != header else []
            while todo:
                current = todo.pop()
                for pred in predecessors[current] - members:
                    members.add(pred); todo.append(pred)
            loops.setdefault(header, set()).update(members)
    for header, members in list(loops.items()):
        exits = {target for node in members for _, target in blocks[node].targets if target not in members}
        if len(exits) > 1: raise Unsupported('loop with multiple exits needs goto output')
        loops[header] = (members, next(iter(exits)) if exits else None)
    return loops


def structured_body(blocks, start, after, pc="U"):
    """Structure reducible CFGs with single-exit natural loops, without goto."""
    nodes = reachable(blocks, start)
    loops = natural_loops(blocks, start, nodes)
    budget = [0]
    cache = {}
    def postdominators(boundaries):
        key = frozenset(boundaries)
        if key in cache: return cache[key]
        universe = nodes | {-1}
        post = {n: universe.copy() for n in nodes}; post[-1] = {-1}
        changed = True
        while changed:
            changed = False
            for n in nodes:
                successors = [] if n in boundaries else [v for _, v in blocks[n].targets]
                value = {n} | set.intersection(*(post[v] for v in (successors or [-1])))
                if value != post[n]: post[n] = value; changed = True
        cache[key] = post
        return post
    def region(current, stop=None, active=(), path=frozenset(), first=False):
        lines = []
        while current is not None and current != stop:
            if active:
                header = active[-1]
                if current == header and not first: return '\n'.join(lines)
                if current == loops[header][1]:
                    lines.append('break'); return '\n'.join(lines)
            if current in loops and current not in active:
                body = region(current, None, active + (current,), path, True)
                lines.append('while true do\n' + indent(body) + '\nend')
                current = loops[current][1]
                continue
            first = False
            if current in path: raise Unsupported('irreducible control flow')
            path = path | {current}
            budget[0] += 1
            if budget[0] > 5000: raise Unsupported('structured output expansion limit')
            block = blocks[current]
            text = emit(block.body)
            if text: lines.append(text)
            if block.terminal:
                if block.terminal_key:
                    lines.append('if ' + pc + ' then error("unresolved dynamic Vmify exit", 0) end')
                lines.extend(emit(stmt) for stmt in after); return '\n'.join(lines)
            if len(block.targets) == 1:
                current = block.targets[0][1]
                continue
            if len(block.targets) != 2: raise Unsupported('non-binary control flow')
            if hasattr(block, 'condition'):
                condition, yes, no = emit(block.condition), block.true_target, block.false_target
            else:
                condition = pc + ' == ' + str(block.targets[0][0])
                yes, no = block.targets[0][1], block.targets[1][1]
            boundaries = set(active)
            boundaries.update(loops[h][1] for h in active if loops[h][1] is not None)
            if stop is not None: boundaries.add(stop)
            post = postdominators(boundaries)
            common = (post[yes] & post[no]) - {-1}
            join = max(common, key=lambda n: len(post[n])) if common else None
            left = region(yes, join, active, path)
            right = region(no, join, active, path)
            lines.append('if ' + condition + ' then\n' + indent(left) + '\nelse\n' + indent(right) + '\nend')
            current = join
        return '\n'.join(lines)
    return region(start)


def _devirtualize_clean_sample(src: bytes, *, clean_sample=False):
    """Lift a supported constant-array wrapper and numeric Vmify dispatcher.

    The clean profile intentionally changes antitamper behavior and is accepted
    only for the exact supplied sample. The default retains the original exits.
    No Lua interpreter, pickle cache, subprocess or network is used here.
    """
    digest = hashlib.sha256(src).hexdigest()
    if clean_sample and digest != CUT_GRASS_SHA256:
        raise Unsupported("clean profile requires the exact CutGrassAdventure SHA-256")
    try:
        tree = parse_lua(src.decode('latin1'))
    except Exception as exc:
        raise Unsupported("Lua parser rejected the input: " + str(exc)) from exc

    def normalize(node):
        if isinstance(node, N.Index) and node.notation == N.IndexNotation.DOT:
            node.idx = literal(node.idx.id.encode('latin1'))
            node.notation = N.IndexNotation.SQUARE
        if isinstance(node, N.Field) and isinstance(node.key, N.Name) and not node.between_brackets:
            node.key = literal(node.key.id.encode('latin1'))
            node.between_brackets = True
        return fold(node)

    tree = transform(tree, normalize)
    try:
        statements = tree.body.body
        if len(statements) != 1 or not isinstance(statements[0], N.Return):
            raise Unsupported('expected a single returned wrapper call')
        wrapper_call = statements[0].values[0]
        if not isinstance(wrapper_call, N.Call) or not isinstance(wrapper_call.func, N.AnonymousFunction):
            raise Unsupported('expected an anonymous wrapper call')
        outer = wrapper_call.func
        tail = outer.body.body[-1]
        if not isinstance(tail, N.Return) or len(tail.values) != 1:
            raise Unsupported('wrapper must return one VM call')
        vm_call = tail.values[0]
        if not isinstance(vm_call, N.Call) or not isinstance(vm_call.func, N.AnonymousFunction):
            raise Unsupported('wrapper must return an anonymous VM call')
        prefix = outer.body.body[:-1]
        # A constant-only prefix cannot observe or preserve wrapper parameters.
        parameter_names = {n.id for n in outer.args if isinstance(n, N.Name)}
        if any(isinstance(n, (N.Varargs, N.Dots)) or
               isinstance(n, N.Name) and n.id in parameter_names for n in walk(prefix)):
            raise Unsupported('constant prefix references wrapper arguments')
        vm_call, replaced_count = substitute_constant_prefix(prefix, vm_call)
        replaced = [replaced_count]
        # The supplied wrapper forwards its varargs through the VM call itself.
        if wrapper_call.args != [] and not (len(wrapper_call.args) == 1 and isinstance(wrapper_call.args[0], (N.Varargs, N.Dots))):
            raise Unsupported('wrapper call arguments have unsupported side effects')
        source, metadata = lift_dispatcher(vm_call.func, cut_grass=clean_sample)
        output = 'return ' + source + '(' + emit(vm_call.args) + ')\n'
    except (IndexError, AttributeError, KeyError, TypeError, ArithmeticError) as exc:
        raise Unsupported('unsupported VM/prefix structure: ' + str(exc)) from exc
    metadata.update({
        'input_sha256': digest, 'constant_lookups_replaced': replaced[0],
        'full_devirtualization': False, 'source_recovered': False,
        'semantic_equivalence_verified': False,
        'scope': 'payload without antitamper' if clean_sample else 'dispatcher lifting',
        'lua_syntax': 'structured control flow (no goto)' if clean_sample else 'Lua 5.2+ goto',
        'limitations': [
            'Closure factories and shared-upvalue bookkeeping are retained.',
            'Original names, comments and original source cannot be recovered.',
            'External HTTP payloads are not downloaded or devirtualized.',
            'Real Roblox behavior and exhaustive branch equivalence are unverified.',
        ] + (['The pinned profile removes antitamper checks and changes their behavior.'] if clean_sample else
             ['Dynamic exit guards reject truthy environment exits that cannot be resolved statically.']),
    })
    return output, metadata


def substitute_constant_prefix(prefix, tail):
    evaluator = ConstantEvaluator(limit=1000000)
    evaluator.run(N.Block(prefix))
    getters = {stmt.name.id for stmt in prefix if isinstance(stmt, N.LocalFunction)}
    for stmt in prefix:
        if isinstance(stmt, N.LocalFunction) and not (
                len(stmt.body.body) == 1 and isinstance(stmt.body.body[0], N.Return)
                and len(stmt.body.body[0].values) == 1
                and isinstance(stmt.body.body[0].values[0], N.Index)):
            raise Unsupported('constant getter is not a pure array lookup')
    replaced = [0]
    prefix_names = set(evaluator.scope.values) - {'math', 'string', 'table', 'type', 'ipairs'}
    def substitute(node, shadowed=frozenset()):
        if isinstance(node, list):
            return [substitute(n, shadowed) for n in node]
        if not isinstance(node, N.Node):
            return node
        if isinstance(node, N.Call) and isinstance(node.func, N.Name) and node.func.id in getters - shadowed:
            node.args = substitute(node.args, shadowed)
            if len(node.args) != 1 or not isinstance(node.args[0], N.Number):
                raise Unsupported('constant getter requires one numeric argument')
            replaced[0] += 1
            return literal(evaluator.scope.get(node.func.id)(node.args[0].n))
        if isinstance(node, N.Name):
            if node.id in prefix_names - shadowed:
                raise Unsupported('unresolved constant-prefix reference: ' + node.id)
            return node
        if isinstance(node, N.Block):
            local = set(shadowed)
            for i, stmt in enumerate(node.body):
                if isinstance(stmt, N.LocalFunction):
                    local.add(stmt.name.id)
                node.body[i] = substitute(stmt, frozenset(local))
                if isinstance(stmt, N.LocalAssign):
                    local.update(n.id for n in stmt.targets)
            return node
        if isinstance(node, N.LocalAssign):
            node.values = substitute(node.values, shadowed)
            return node
        if isinstance(node, (N.AnonymousFunction, N.Function, N.LocalFunction)):
            if isinstance(node, N.Function):
                node.name = substitute(node.name, shadowed)
            args = {n.id for n in node.args if isinstance(n, N.Name)}
            node.body = substitute(node.body, shadowed | args)
            return node
        if isinstance(node, N.Fornum):
            node.start = substitute(node.start, shadowed)
            node.stop = substitute(node.stop, shadowed)
            if isinstance(node.step, N.Node):
                node.step = substitute(node.step, shadowed)
            node.body = substitute(node.body, shadowed | {node.target.id})
            return node
        if isinstance(node, N.Forin):
            node.iter = substitute(node.iter, shadowed)
            node.body = substitute(node.body, shadowed | {n.id for n in node.targets})
            return node
        for key, value in list(fields(node)):
            if isinstance(value, (N.Node, list)):
                setattr(node, key, substitute(value, shadowed))
        return node
    return substitute(copy.deepcopy(tail)), replaced[0]


def normalize_ast(tree):
    def normalize(node):
        if isinstance(node, N.Index) and node.notation == N.IndexNotation.DOT:
            node.idx = literal(node.idx.id.encode('latin1'))
            node.notation = N.IndexNotation.SQUARE
        if isinstance(node, N.Field) and isinstance(node.key, N.Name) and not node.between_brackets:
            node.key = literal(node.key.id.encode('latin1'))
            node.between_brackets = True
        return fold(node)
    return transform(tree, normalize)


def devirtualize(src: bytes, *, clean_sample=False, structured=True, remove_antitamper=False):
    """Detect standard Vmify containers structurally, independent of seeds/files.

    Constant-array wrappers are optional. Application code is never executed.
    Other transformations (including antitamper and string encryption) remain
    unless the user explicitly selects the legacy, pinned clean-sample profile.
    """
    if clean_sample:
        return _devirtualize_clean_sample(src, clean_sample=True)
    try:
        tree = normalize_ast(parse_lua(src.decode('latin1')))
    except Exception as exc:
        raise Unsupported('Lua parser rejected input: ' + str(exc)) from exc
    prefix_records, lifted, failed = [], [], []
    used = {n.id for n in walk(tree) if isinstance(n, N.Name)}
    def constants(node):
        if isinstance(node, N.AnonymousFunction):
            statements = node.body.body
        elif isinstance(node, N.Block):
            statements = node.body
        else:
            return node
        if len(statements) < 2: return node
        prefix, tail = statements[:-1], statements[-1]
        if (not isinstance(tail, N.Return) or not isinstance(prefix[0], N.LocalAssign)
                or not any(isinstance(n, N.Table) for n in prefix[0].values)
                or not any(isinstance(n, N.LocalFunction) for n in prefix)):
            return node
        try:
            replacement, count = substitute_constant_prefix(prefix, tail)
        except (Unsupported, TypeError, AttributeError, KeyError, ArithmeticError) as exc:
            prefix_records.append({'status': 'retained', 'reason': str(exc)})
        else:
            if isinstance(node, N.Block): node.body = [replacement]
            else: node.body.body = [replacement]
            prefix_records.append({'status': 'inlined', 'lookups': count})
        return node
    # Process outer constant arrays before trying the containers they enclose.
    def outer_first(node):
        if isinstance(node, list): return [outer_first(n) for n in node]
        if not isinstance(node, N.Node): return node
        node = constants(node)
        for key, value in list(fields(node)):
            if isinstance(value, (N.Node, list)): setattr(node, key, outer_first(value))
        return node
    tree = outer_first(tree)
    def candidate(node):
        if not isinstance(node, N.Call) or not isinstance(node.func, N.AnonymousFunction):
            return False
        stats = node.func.body.body
        if len(stats) != 2 or not isinstance(stats[0], N.Assign) or isinstance(stats[0], N.LocalAssign) or not isinstance(stats[1], N.Return):
            return False
        return any(isinstance(v, N.AnonymousFunction) and v.args and isinstance(v.args[0], N.Name)
                   and any(isinstance(n, N.While) and isinstance(n.test, N.Name) and n.test.id == v.args[0].id for n in v.body.body)
                   for v in stats[0].values)
    def lift(node):
        if not candidate(node): return node
        environment = None
        for param, arg in zip(node.func.args, node.args):
            if isinstance(param, N.Name) and any(isinstance(n, N.Name) and n.id in ('_ENV', 'getfenv') for n in walk(arg)):
                environment = param.id
                break
        if environment is None:
            failed.append({'reason': 'cannot identify the environment parameter'})
            return node
        native, suffix = 'recovered_functions', 1
        while native in used:
            suffix += 1
            native = 'recovered_functions_' + str(suffix)
        try:
            source, report = lift_dispatcher(copy.deepcopy(node.func), environment_name=environment, native=native, structured=structured, remove_antitamper=remove_antitamper)
            replacement = LiftedExpression(source)
        except (Unsupported, AttributeError, KeyError, IndexError, TypeError, ArithmeticError) as exc:
            failed.append({'reason': str(exc)})
            return node
        used.add(native)
        node.func = replacement
        report.update({'container': len(lifted) + 1, 'environment_parameter': environment, 'function_table': native})
        lifted.append(report)
        return node
    tree = transform(tree, lift)
    if not lifted:
        reasons = '; '.join(x['reason'] for x in failed) or 'no supported Vmify container found'
        retained = '; '.join(r['reason'] for r in prefix_records if r['status'] == 'retained')
        raise Unsupported(reasons + ('; constant prefix: ' + retained if retained else ''))
    if failed:
        raise Unsupported('some Vmify containers could not be lifted: ' + '; '.join(x['reason'] for x in failed))
    source = emit(tree) + '\n'
    metadata = {
        'input_sha256': hashlib.sha256(src).hexdigest(), 'dispatcher_removed': True,
        'containers_lifted': len(lifted), 'containers': lifted,
        'vm_blocks': sum(r['vm_blocks'] for r in lifted),
        'native_functions': sum(r['native_functions'] for r in lifted),
        'constant_lookups_replaced': sum(r.get('lookups', 0) for r in prefix_records),
        'constant_prefixes': prefix_records, 'decoded_strings': [],
        'antitamper_removed': any(r['antitamper_removed'] for r in lifted), 'antitamper_bypassed': any(r['antitamper_bypassed'] for r in lifted), 'profile': 'structural Vmify detection',
        'full_devirtualization': False, 'source_recovered': False,
        'semantic_equivalence_verified': False,
        'lua_syntax': 'Lua 5.2+ goto' if not structured or any(r['structured_fallbacks'] for r in lifted) or any(isinstance(n, N.Goto) for n in walk(tree)) else 'structured control flow (no goto)',
        'limitations': [
            'String encryption and closure/upvalue helpers are retained; the known final antitamper guard can be bypassed explicitly.',
            'Nested interpreters compiled into another VM may remain.',
            'Dynamic exit guards reject truthy environment exits that cannot be resolved statically.',
            'Original source/names and external payloads are not recovered.',
            'Unsupported custom VM layouts and Luau syntax are rejected.',
        ],
    }
    return source, metadata


def find_antitamper_boundary(blocks, entries, main_calls, locate):
    """Recognize the stock error-marker + trap-closure + final validation guard.

    The opt-in bypass keeps all initialization and skips only the final trap arm.
    It rejects ambiguous matches instead of guessing a payload offset.
    """
    if not any(isinstance(n, N.String) and n.s == b'Tamper Detected!' for b in blocks for n in walk(b.body)):
        return None
    if any(isinstance(n, N.String) and n.s == b'sethook' for b in blocks for n in walk(b.body)):
        raise Unsupported('debug-hook antitamper requires a separate transformation')
    if len(main_calls) != 1 or not main_calls[0].args or not isinstance(main_calls[0].args[0], N.Number):
        raise Unsupported('antitamper bypass cannot identify the main entry')
    main = main_calls[0].args[0].n
    main_nodes = reachable(blocks, locate(main))
    traps = {entry for entry in entries - {main} if not any(blocks[n].terminal for n in reachable(blocks, locate(entry)))}
    def contains_trap(block):
        return any(isinstance(n, N.Call) and n.args and isinstance(n.args[0], N.Number) and n.args[0].n in traps
                   for n in walk(block.body))
    def trap_path(start):
        seen = set()
        while start not in seen:
            seen.add(start)
            block = blocks[start]
            if contains_trap(block) and block.terminal: return True
            if len(block.targets) != 1: return False
            start = block.targets[0][1]
        return False
    matches = []
    for bid in main_nodes:
        block = blocks[bid]
        if len(block.targets) != 2: continue
        left, right = [target for _, target in block.targets]
        a, b = trap_path(left), trap_path(right)
        if a != b:
            state, target = block.targets[1] if a else block.targets[0]
            matches.append((main, bid, state, target))
    matches = sorted(set(matches))
    if len(matches) != 1:
        raise Unsupported('stock antitamper boundary is ambiguous or unsupported')
    return matches[0]
