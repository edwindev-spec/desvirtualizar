"""Differential checks for dispatcher lifting, not just formatting assertions."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import prometheus_devirt_100 as cli

HAS_PARSER = importlib.util.find_spec('luaparser') is not None
if HAS_PARSER:
    import prometheus_static as static

FIXTURE = '''return (function(...)
  local strings = {"yes", "no"}
  local function lookup(n) return strings[n] end
  return (function(env, unpack_values, dispatch, factory)
    dispatch, factory = function(pc, args, captured)
      local result
      while pc do
        if pc < 10 then
          pc = args[1] and 15 or 25
        else
          if pc < 20 then
            result = {lookup(1), args[2], nil, args[4]}
            pc = nil
          else
            result = {lookup(2), args[2], nil, args[4]}
            pc = nil
          end
        end
      end
      return unpack_values(result, 1, 4)
    end, function(entry, captured)
      return function(...) return dispatch(entry, {...}, captured) end
    end
    return factory(5, {})
  end)(_ENV, table.unpack)
end)(...)'''

LOOP_FIXTURE = '''return (function(...)
  return (function(env, unpack_values, dispatch, factory)
    dispatch, factory = function(pc, args, captured)
      local count, result
      while pc do
        if pc < 10 then
          count = 0
          pc = 15
        else
          if pc < 20 then
            pc = count < args[1] and 25 or 35
          else
            if pc < 30 then
              count = count + 1
              captured[1] = captured[1] + count
              pc = 15
            else
              result = {count, captured[1]}
              pc = nil
            end
          end
        end
      end
      return unpack_values(result)
    end, function(entry, captured)
      return function(...) return dispatch(entry, {...}, captured) end
    end
    return factory(5, {0})
  end)(_ENV, table.unpack)
end)(...)'''


@unittest.skipUnless(HAS_PARSER, 'optional luaparser dependency required')
class StaticTests(unittest.TestCase):
    def test_lift_without_runtime_and_reject_unknown_profile(self):
        text, report = static.devirtualize(FIXTURE.encode())
        self.assertEqual(report['native_functions'], 1)
        self.assertEqual(report['constant_lookups_replaced'], 2)
        self.assertTrue(report['dispatcher_removed'])
        self.assertFalse(report['semantic_equivalence_verified'])
        self.assertNotIn('while pc do', text)
        with self.assertRaises(static.Unsupported):
            static.devirtualize(FIXTURE.encode(), clean_sample=True)
        with self.assertRaises(static.Unsupported):
            static.devirtualize(b'print("unsupported")')

    def test_getter_shadowing(self):
        # Same spelling in a nested function must keep its parameter binding.
        source = FIXTURE.replace('function(entry, captured)', 'function(entry, lookup)')
        source = source.replace('dispatch(entry, {...}, captured)', 'dispatch(entry, {...}, lookup)')
        text, report = static.devirtualize(source.encode())
        self.assertEqual(report['constant_lookups_replaced'], 2)
        self.assertIn('lookup)', text)
        escaping = FIXTURE.replace('return factory(5, {})', 'return factory(5, {lookup})')
        output, report = static.devirtualize(escaping.encode())
        self.assertEqual(report['constant_prefixes'][0]['status'], 'retained')
        self.assertIn('local function lookup', output)

    def test_cli_static_success_and_unsupported_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'input.lua'
            src.write_text(FIXTURE)
            code = cli.main([str(src), '--solo-estatico', '--desvirtualizar', '-o', str(root/'out')])
            self.assertEqual(code, 0)
            report = json.loads((root/'out/report.json').read_text())
            self.assertEqual(report['static_vm']['status'], 'lifted')
            self.assertFalse(report['full_devirtualization'])
            self.assertTrue((root/'out/vm_removed.lua').exists())
            code = cli.main([str(src), '--solo-estatico', '--perfil-cutgrass', '-o', str(root/'bad')])
            self.assertEqual(code, 3)
            self.assertFalse((root/'bad/vm_removed.lua').exists())
            report = json.loads((root/'bad/report.json').read_text())
            self.assertEqual(report['static_vm']['status'], 'unsupported')

    @unittest.skipUnless(shutil.which('lua'), 'Lua required for differential validation')
    def test_differential_returns_branches_nil_and_shared_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [(FIXTURE, '''local fn = assert(loadfile(arg[1]))()
for _, value in ipairs({false, true, 0, ""}) do
  local values = table.pack(fn(value, 7, nil, 11))
  print(values.n, tostring(values[1]), tostring(values[2]), tostring(values[3]), tostring(values[4]))
end'''), (LOOP_FIXTURE, '''local fn = assert(loadfile(arg[1]))()
for _, n in ipairs({0, 1, 5, 2}) do print(fn(n)) end''')]
            driver = root / 'driver.lua'
            for original, script in cases:
                lifted, _ = static.devirtualize(original.encode())
                a, b = root/'original.lua', root/'lifted.lua'
                a.write_text(original)
                b.write_text(lifted)
                driver.write_text(script)
                runs = [subprocess.run(['lua', str(driver), str(p)], capture_output=True, timeout=3) for p in (a,b)]
                for run in runs:
                    self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(runs[0].stdout, runs[1].stdout)
                self.assertTrue(runs[0].stdout)


@unittest.skipUnless(HAS_PARSER and shutil.which('lua'), 'luaparser and Lua required')
class GeneralVmTests(unittest.TestCase):
    def compare(self, original, **options):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lifted, report = static.devirtualize(original.encode('latin1'), **options)
            driver = root/'driver.lua'
            driver.write_text('getfenv=function() return _G end\nmath.randomseed(1234)\nlocal function show(...) print("RETURNS", select("#",...), ...) end\n'
                              'local fn=assert(loadfile(arg[1]))()\nif type(fn)=="function" then '
                              'for _,v in ipairs({false,true,0,""}) do show(fn(v,7,nil,11)) end '
                              'else show(fn) end\n')
            results = []
            for name, text in (('original.lua', original), ('lifted.lua', lifted)):
                path = root/name
                path.write_bytes(text.encode('latin1'))
                run = subprocess.run(['lua', str(driver), str(path)],
                                     capture_output=True, timeout=4)
                self.assertEqual(run.returncode, 0, run.stderr)
                results.append(run.stdout)
            self.assertEqual(*results)
            return lifted, report

    def test_threshold_variants_direct_vm_and_one_block(self):
        variants = [FIXTURE.replace('pc < 10', '10 > pc').replace('pc < 20', 'pc <= 19'),
                    FIXTURE.replace('pc < 10', 'not (pc >= 10)')]
        # Negated custom dispatchers are rejected explicitly, not mispartitioned.
        with self.assertRaises(static.Unsupported):
            static.devirtualize(variants.pop().encode())
        for source in (variants[0], FIXTURE.replace('else\n          if pc < 20 then', 'elseif pc < 20 then')
                       .replace('          end\n        end\n      end', '        end\n      end')):
            with self.subTest(source=source[:25]):
                self.compare(source)
        direct = '''return (function(env, dispatch, factory)
          dispatch, factory = function(pc)
            local result
            while pc do result = 42; pc = nil end
            return result
          end, function(entry) return function() return dispatch(entry) end end
          return factory(3.0)()
        end)(_ENV)'''
        output, report = self.compare(direct)
        self.assertEqual(report['vm_blocks'], 1)
        self.assertNotIn('while pc', output)

    def test_binary_strings_roundtrip_and_opaque_prefix(self):
        source = FIXTURE.replace('"yes"', '"\\000\\128\\195\\255"').replace('"no"', '"\\255\\000\\010"')
        output, _ = self.compare(source)
        self.assertIn('\\255', output)
        # Raw high bytes must also survive parser normalization and emission.
        source = FIXTURE.replace('"yes"', '"\xff\x80"')
        self.compare(source)
        escaped = FIXTURE.replace('return factory(5, {})', 'return factory(5, {lookup})')
        _, report = self.compare(escaped)
        self.assertEqual(report['constant_prefixes'][0]['status'], 'retained')

    def test_multiple_containers_and_identifier_collisions(self):
        expression = FIXTURE.removeprefix('return ')
        source = 'local recovered_functions={}\nlocal a='+expression+'\nlocal b='+expression+'\nreturn a,b'
        # The two returned closures share no generated table accidentally.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            lifted, report=static.devirtualize(source.encode())
            self.assertEqual(report['containers_lifted'], 2)
            self.assertEqual(len({r['function_table'] for r in report['containers']}), 2)
            driver=root/'driver.lua'
            driver.write_text('local a,b=assert(loadfile(arg[1]))()\nprint(a(false,7,nil,11)); print(b(true,8,nil,12))')
            runs=[]
            for name,text in (('a.lua',source),('b.lua',lifted)):
                path=root/name;path.write_text(text)
                run=subprocess.run(['lua',str(driver),str(path)],capture_output=True,timeout=4)
                self.assertEqual(run.returncode,0,run.stderr)
                runs.append(run.stdout)
            self.assertEqual(*runs)

    def test_ambiguous_antitamper_and_invalid_lua_are_rejected(self):
        with self.assertRaises(static.Unsupported):
            static.devirtualize(FIXTURE.replace('"yes"','"Tamper Detected!"').encode(), remove_antitamper=True)
        with self.assertRaises(static.Unsupported):
            static.devirtualize(b'return function(')

    def test_unvirtualized_methods_and_wrapped_multiple_returns(self):
        expression = FIXTURE.removeprefix('return ')
        source = ('local object={}\nfunction object.method(value) return value, 99 end\n'
                  'function object:run(value) return value, 88 end\n'
                  'local first=(object:run(3)); local second=object.method(4)\n'
                  'print(first, second)\nreturn '+expression)
        self.compare(source)

    def test_stateful_getter_prefix_is_preserved(self):
        source = FIXTURE.replace('return strings[n] end', 'strings[n]=strings[n].."!"; return strings[n] end')
        _,report = self.compare(source)
        self.assertEqual(report['constant_prefixes'][0]['status'], 'retained')

    @unittest.skipUnless(shutil.which('luajit'), 'LuaJIT required for stock Lua 5.1 fixtures')
    def test_official_presets_three_seeds(self):
        fixtures = Path(__file__).parent/'fixtures/prometheus'
        manifest=json.loads((fixtures/'manifest.json').read_text())
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            driver=root/'driver.lua'
            driver.write_text('getfenv=function() return _G end\nmath.randomseed(1234)\nlocal function show(...) print("RETURNS",select("#",...),...) end\n'
                              'show(assert(loadfile(arg[1]))())')
            expected=subprocess.run(['luajit',str(driver),str(fixtures/'source.lua')],capture_output=True,timeout=4)
            self.assertEqual(expected.returncode,0,expected.stderr)
            for preset in ('Vmify','Weak','Medium','Strong'):
                for seed in manifest['seeds']:
                    name=f'{preset}_{seed}.lua'
                    with self.subTest(preset=preset,seed=seed):
                        path=fixtures/name;src=path.read_bytes()
                        self.assertEqual(hashlib.sha256(src).hexdigest(),manifest['sha256'][name])
                        original=subprocess.run(['luajit',str(driver),str(path)],capture_output=True,timeout=4)
                        self.assertEqual(original.returncode,0,original.stderr)
                        self.assertEqual(original.stdout,expected.stdout)
                        text,report=static.devirtualize(src,remove_antitamper=preset in ('Medium','Strong'))
                        output=root/name;output.write_text(text)
                        result=subprocess.run(['luajit',str(driver),str(output)],capture_output=True,timeout=4)
                        self.assertEqual(result.returncode,0,result.stderr)
                        self.assertEqual(result.stdout,expected.stdout)
                        self.assertFalse(report['full_devirtualization'])
                        if preset in ('Medium','Strong'):
                            self.assertTrue(report['antitamper_bypassed'])
                            self.assertFalse(report['antitamper_removed'])
