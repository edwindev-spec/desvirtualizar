import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import prometheus_devirt_100 as devirt


class StaticTests(unittest.TestCase):
    def test_nested_blocks_comments_and_strings(self):
        src = b'''local text = "function() end"
-- function ignored() end
local function outer(x)
  for i=1,2 do while x do x=false end end
  repeat x=true until x
  return function(...) if x then do return ... end end end
end
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = devirt.index_source_functions(src, root)
            self.assertEqual(result['status'], 'indexed')
            outer, inner = result['functions']
            self.assertEqual(inner['parent'], outer['id'])
            self.assertEqual(inner['parameters_text'], '...')
            self.assertEqual(src[inner['start_byte']:inner['end_byte']],
                             b'function(...) if x then do return ... end end end')
            self.assertEqual((root / outer['file']).read_bytes(), src)

    def test_static_mode_does_not_need_lua(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'input.lua'
            src.write_text('return function() return "never executed" end')
            self.assertEqual(devirt.main([str(src), '-o', str(root/'out'), '--solo-estatico',
                                          '--lua', '/no/runtime']), 0)
            report = json.loads((root/'out/report.json').read_text())
            self.assertEqual(report['source_functions']['count'], 1)
            self.assertFalse(report['full_devirtualization'])
            self.assertFalse((root/'out/reconstructed.lua').exists())

    def test_interrupted_event_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'functions.tsv').write_text('register\tfn1\t40\t1\t2\t1\tfalse\nstatus\tfn1\trunning\n')
            (root/'trace_events.hex').write_bytes(b'fn1\t'+b'print("fn1 v1")'.hex().encode()+b'\nfn1\t0')
            result = devirt.reconstruct_functions(root)
            self.assertEqual(result['functions'][0]['status'], 'interrupted')
            self.assertIn(b'print("fn1 v1")', (root/'reconstructed.lua').read_bytes())
            self.assertEqual(result['observed'], 0)


@unittest.skipUnless(shutil.which('lua'), 'Lua runtime required')
class DynamicTests(unittest.TestCase):
    def run_lua(self, source, *options):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        target = root/'input.lua'
        target.write_text(source)
        code = devirt.main([str(target), '-o', str(root/'out'), '--lua', 'lua', '-y',
                           '--timeout', '3', *options])
        result = json.loads((root/'out/functions.json').read_text())
        reconstructed = (root/'out/reconstructed.lua').read_text()
        check = subprocess.run(['lua', '-e', 'assert(loadfile('+devirt.lua_literal(
            str(root/'out/reconstructed.lua').encode())+'))'], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        return code, result, reconstructed, root/'out'

    def test_globals_nested_returns_and_nil_arity(self):
        code, result, output, root = self.run_lua('''
function exported(x) print("outer", x); return nil, function() print("inner"); return 7, nil end, nil end
return exported
''')
        self.assertEqual(code, 0)
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['observed'], 2)
        self.assertIn('return nil, functions.fn2, nil', output)
        self.assertIn('return 7, nil', output)
        self.assertIn('print("outer", arg1)', (root/'functions/fn1.lua').read_text())
        self.assertNotIn('print("inner")', (root/'functions/fn1.lua').read_text())
        self.assertIn('print("inner")', (root/'functions/fn2.lua').read_text())

    def test_ui_values_and_wait_limit_continue(self):
        code, result, output, root = self.run_lua('''
game:AddToggle({state=false, callback=function(v) print("enabled", v) end})
game:AddSlider({value=18, callback=function(v) print("speed", v) end})
task.spawn(function() while true do task.wait(); game:Tick() end end)
task.spawn(function() print("after loop") end)
''', '--branch-policy', 'true', '--max-waits', '2')
        self.assertEqual(code, 3)
        self.assertIn('print("enabled", true)', output)
        self.assertIn('print("speed", 18)', output)
        self.assertIn('print("after loop")', output)
        self.assertEqual(output.count(':Tick()'), 2)
        self.assertEqual([r['status'] for r in result['functions']],
                         ['observed', 'observed', 'wait_limit', 'observed'])

    def test_no_callbacks_keeps_unexecuted_placeholders(self):
        code, result, output, root = self.run_lua('game:Connect(function() print("hidden") end)', '--no-callbacks')
        self.assertEqual(code, 0)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['observed'], 0)
        self.assertEqual(result['functions'][0]['status'], 'not_executed')
        self.assertNotIn('print("hidden")', output)

    def test_callback_limit_does_not_drop_function_inventory(self):
        code, result, output, root = self.run_lua('''
game:Connect(function() print("first") end)
game:Connect(function() print("second") end)
''', '--max-callbacks', '1')
        self.assertEqual(code, 3)
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['observed'], 1)

    def test_multi_explores_both_policies_without_ghost_all(self):
        code, result, output, root = self.run_lua(
            'game:AddToggle({state=false, callback=function(v) print("toggle", v) end})', '--multi')
        self.assertEqual(code, 0)
        report = json.loads((root/'report.json').read_text())
        self.assertEqual([(p['ghost_all'], p['branch_policy']) for p in report['passes']],
                         [(False, 'false'), (False, 'true'), (True, 'false'), (True, 'true')])
        self.assertIn('print("toggle", false)', (root/'pass_01/reconstructed.lua').read_text())
        self.assertIn('print("toggle", true)', (root/'pass_02/reconstructed.lua').read_text())

    def test_shared_results_and_upvalue_metadata(self):
        code, result, output, root = self.run_lua('''
local service=game:GetService("Players")
local entry=12345
game:Connect(function() service:Use(entry); return service end)
''')
        self.assertEqual(code, 0)
        self.assertIn('values.v1:Use(12345)', output)
        self.assertIn('return values.v1', output)
        self.assertEqual(result['functions'][0]['upvalues'][0]['name'], 'entry')


if __name__ == '__main__':
    unittest.main()
