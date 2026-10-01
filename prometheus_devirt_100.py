#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prometheus_devirt_100.py — analisis dinamico y estatico de Lua/Prometheus.
Python >= 3.9, sin dependencias de Python. Lua 5.1 / LuaJIT recomendado;
tambien admite Lua 5.2-5.4. No implementa el lenguaje Luau.

El nombre conserva el del archivo original del usuario: no implica recuperacion
al 100 %. La salida devirt.lua es una traza parcial, NO codigo equivalente al
original. No reconstruye el grafo de control ni elimina la VM de Vmify.

Salidas:
  report.json           estados, limites, hash de entrada y procedencias
  normalized.lua        literales reescritos sin ejecutar (no elimina Vmify)
  devirt.lua            traza cronologica de la pasada seleccionada
  reconstructed.lua     efectos observados agrupados en cuerpos de funciones
  functions.json        estados, upvalues y procedencia de cada closure observada
  functions/            fragmentos de los cuerpos observados
  source_functions.json indice estatico de TODAS las funciones sintacticas
  source_functions.lua  fuente original para consultar spans exactos del indice
  pass_XX/              todas las trazas, estados, metricas y payloads
  payloads/<sha256>.lua  payloads unicos capturados, con sus bytes originales
  dynamic_strings.json  cadenas observadas, origen y bytes en hexadecimal
  strings.txt           literales/cadenas legibles y URLs

La captura dinamica observa string.char, table.concat y argumentos registrados;
puede contener tanto cadenas cifradas como descifradas. decrypted.txt solo recoge
una cache global STRINGS si esta existe. No se descargan recursos HTTP.

Uso:
  python3 prometheus_devirt_100.py muestra.lua --solo-estatico
  python3 prometheus_devirt_100.py muestra.lua --lua lua5.1 -y
  python3 prometheus_devirt_100.py muestra.lua --multi --timeout 10 -o resultado

La ejecucion usa APIs simuladas y bibliotecas copiadas. Los limites POSIX acotan
CPU, memoria y archivos; el limite de tiempo real tambien funciona en Windows.
Esto NO proporciona aislamiento de sistema operativo: ejecuta muestras no
confiables en un contenedor/VM desechable sin red. Los fantasmas, las comparaciones
y los callbacks sinteticos alteran el comportamiento. No hay medida de cobertura.
Codigos de salida: 0 analisis terminado; 2 configuracion/cancelacion; 3 parcial;
130 interrupcion. Incluso un estado ok no significa desvirtualizacion completa.
"""
from __future__ import annotations

import argparse
import json
import hashlib
import math
import signal
import time
from dataclasses import asdict, dataclass
from types import SimpleNamespace
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

__version__ = "3.1.0"

# ---------------------------------------------------------------------------
#  Arnes Lua (se escribe como harness.lua y se ejecuta con luajit/lua5.1/lua)
# ---------------------------------------------------------------------------
HARNESS_LUA = r'''
-- prometheus_devirt :: arnes Lua
-- args: objetivo salida cpu_s ghosts_csv ghost_all reservado callbacks comparacion max_callbacks payload_bytes
local TARGET, OUTDIR = arg[1], arg[2]
local CPU_LIMIT = tonumber(arg[3]) or 20
local EXTRA_GHOSTS = arg[4] or ""
local GHOST_ALL = (arg[5] == "1")
local RUN_CALLBACKS = (arg[7] ~= "0")
local BRANCH_TRUE = (arg[8] == "true")
local MAX_CALLBACKS = tonumber(arg[9]) or 100
local MAX_PAYLOAD_BYTES = tonumber(arg[10]) or 16777216
local MAX_WAITS = tonumber(arg[11]) or 3
local MAX_PAYLOADS = 128
-- Los hooks de instrucciones no detienen bucles compilados por LuaJIT.
if jit then jit.off(); jit.flush() end

-- Copias locales de lo "real": el script analizado no puede alterarlas.
local G = _G
local type, tostring, tonumber, pairs, ipairs = type, tostring, tonumber, pairs, ipairs
local next, select, rawget, rawset, rawequal = next, select, rawget, rawset, rawequal
local setmetatable, getmetatable, pcall, xpcall, error = setmetatable, getmetatable, pcall, xpcall, error
local sformat, sbyte, ssub, sgsub, smatch, sgmatch = string.format, string.byte, string.sub, string.gsub, string.match, string.gmatch
local tconcat, tsort = table.concat, table.sort
local mfloor, mhuge, mabs = math.floor, math.huge, math.abs
local io_open, io_stderr = io.open, io.stderr
local os_exit, os_clock, os_time, os_date, os_difftime = os.exit, os.clock, os.time, os.date, os.difftime
local d_sethook = debug and debug.sethook
local d_traceback = debug and debug.traceback
local d_getinfo = debug and debug.getinfo
local d_getupvalue = debug and debug.getupvalue
local loadstring_real, load_real = loadstring, load
local setfenv_real, getfenv_real = setfenv, getfenv
local unpack_ = unpack or table.unpack
local newproxy_real = newproxy
local co_create, co_resume = coroutine.create, coroutine.resume

local EXIT_TAG, CB_TIMEOUT, WAIT_LIMIT = {}, {}, {}
local wait_count = 0
local finishing = false
local metrics = {calls = 0, assignments = 0, callbacks = 0, callback_errors = 0,
  callback_timeouts = 0, callback_limit = 0, wait_limits = 0, comparisons = 0, blocked = 0,
  payloads = 0, dynamic_strings = 0, string_limit = 0, format_truncations = 0}
local dynamic_file = assert(io_open(OUTDIR .. "/dynamic_strings.hex", "wb"))
local dynamic_seen, dynamic_bytes = {}, 0
local function observe(s, origin)
  if type(s) ~= "string" or #s < 4 or dynamic_seen[s] then return end
  if #s > 65536 or dynamic_bytes + #s > 4194304 or metrics.dynamic_strings >= 10000 then
    metrics.string_limit = 1
    return
  end
  dynamic_seen[s] = true
  dynamic_bytes = dynamic_bytes + #s
  metrics.dynamic_strings = metrics.dynamic_strings + 1
  dynamic_file:write(origin, "\t", (sgsub(s, ".", function(c) return sformat("%02x", sbyte(c)) end)), "\n")
  dynamic_file:flush()
end
local finish -- se define al final

-- ---------------------------------------------------------------- salida
local logf = assert(io_open(OUTDIR .. "/devirt.lua", "wb"))
logf:setvbuf("line")
local nlines, nbytes, finished = 0, 0, false
local eventf = assert(io_open(OUTDIR .. "/trace_events.hex", "wb"))
eventf:setvbuf("line")
local functionf = assert(io_open(OUTDIR .. "/functions.tsv", "wb"))
functionf:setvbuf("line")
local context = "main"
local function hex(s)
  return (sgsub(s, ".", function(c) return sformat("%02x", sbyte(c)) end))
end
local MAX_LOG = 32 * 1024 * 1024

local function emit(s)
  if finished then return end
  nlines = nlines + 1
  nbytes = nbytes + #s + 1
  logf:write(s, "\n")
  eventf:write(context, "\t", hex(s), "\n")
  if nlines % 100 == 0 then logf:flush() end
  if nbytes > MAX_LOG then
    logf:write("-- [LIMITE] el log supero 32 MB; ejecucion cortada\n")
    finish("log_limit")
  end
end

local function readfile(path)
  local f = io_open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

-- ------------------------------------------------------------ formateo
local KEYWORDS = {}
for w in sgmatch("and break do else elseif end false for function goto if in local nil not or repeat return then true until while", "%a+") do
  KEYWORDS[w] = true
end

local function is_ident(k)
  return type(k) == "string" and smatch(k, "^[%a_][%w_]*$") ~= nil and not KEYWORDS[k]
end

local function qstr(s)
  local extra = ""
  if #s > 3000 then
    metrics.format_truncations = metrics.format_truncations + 1
    extra = sformat(" --[[+%d bytes]]", #s - 3000)
    s = ssub(s, 1, 3000)
  end
  return '"' .. sgsub(s, '[%c"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    if c == "\n" then return "\\n" end
    if c == "\r" then return "\\r" end
    if c == "\t" then return "\\t" end
    return sformat("\\%03d", sbyte(c))
  end) .. '"' .. extra
end

local function fnum(n)
  if n ~= n then return "(0/0)" end
  if n == mhuge then return "math.huge" end
  if n == -mhuge then return "-math.huge" end
  if n == mfloor(n) and mabs(n) < 1e15 then return sformat("%.0f", n) end
  return sformat("%.14g", n)
end

local gdata = setmetatable({}, {__mode = "k"}) -- fantasma -> {path, parent, key, kids}
local names = setmetatable({}, {__mode = "k"}) -- objeto -> nombre de variable
local counters = {v = 0, fn = 0}
local fmt
local function_records = {}
local function register_function(f)
  local nm = names[f]
  if nm then return nm end
  counters.fn = counters.fn + 1
  nm = "fn" .. counters.fn
  names[f] = nm
  local info = d_getinfo and d_getinfo(f, "Su") or {}
  function_records[nm] = {fn = f, status = "not_executed"}
  functionf:write("register\t", nm, "\t", hex(info.source or ""), "\t",
    tostring(info.linedefined or -1), "\t", tostring(info.lastlinedefined or -1), "\t",
    tostring(info.nparams or -1), "\t", tostring(info.isvararg), "\n")
  -- Los escalares capturados incluyen el estado de entrada de closures Vmify.
  if d_getupvalue then
    for index = 1, 255 do
      local key, value = d_getupvalue(f, index)
      if not key then break end
      local kind = type(value)
      if kind == "number" or kind == "boolean" or kind == "string" or kind == "nil" then
        local rendered = kind == "string" and value or tostring(value)
        functionf:write("upvalue\t", nm, "\t", hex(key), "\t", kind, "\t", hex(ssub(rendered, 1, 65536)), "\n")
      end
    end
  end
  return nm
end

local function fmt_table(t, depth, seen)
  if seen[t] then return "{--[[ciclo]]}" end
  if depth > 3 then return "{--[[profundidad omitida]]}" end
  seen[t] = true
  local parts, count, i = {}, 0, 1
  while true do
    local v = rawget(t, i)
    if v == nil then break end
    count = count + 1
    if count > 12 then metrics.format_truncations = metrics.format_truncations + 1; parts[#parts + 1] = "--[[elementos omitidos]]"; break end
    parts[#parts + 1] = fmt(v, depth + 1, seen)
    i = i + 1
  end
  if count <= 12 then
    local keys = {}
    for k in next, t do
      if not (type(k) == "number" and k >= 1 and k < i and k == mfloor(k)) then keys[#keys + 1] = k end
    end
    pcall(tsort, keys, function(a, b)
      local ta, tb = type(a), type(b)
      if ta ~= tb then return ta < tb end
      if ta == "string" or ta == "number" then return a < b end
      return false
    end)
    for _, k in ipairs(keys) do
      count = count + 1
      if count > 12 then metrics.format_truncations = metrics.format_truncations + 1; parts[#parts + 1] = "--[[elementos omitidos]]"; break end
      local ks = is_ident(k) and k or ("[" .. fmt(k, depth + 1, seen) .. "]")
      parts[#parts + 1] = ks .. " = " .. fmt(rawget(t, k), depth + 1, seen)
    end
  end
  seen[t] = nil
  return "{" .. tconcat(parts, ", ") .. "}"
end

function fmt(v, depth, seen)
  local tv = type(v)
  if tv == "string" then observe(v, "trace"); return qstr(v) end
  if tv == "number" then return fnum(v) end
  if tv == "boolean" or tv == "nil" then return tostring(v) end
  if tv == "function" then
    return register_function(v)
  end
  if tv == "table" then
    local gd = gdata[v]
    if gd then return names[v] or gd.path end
    return fmt_table(v, depth or 0, seen or {})
  end
  return "nil --[[" .. tv .. " no representable]]"
end

local function fmt_list(args, from, to)
  local parts = {}
  for i = from, to do parts[#parts + 1] = fmt(args[i]) end
  return tconcat(parts, ", ")
end

-- ----------------------------------------------- cola de callbacks/tareas
local cb_queue, cb_seen = {}, setmetatable({}, {__mode = "k"})
local function queue_fn(f, args, n)
  if type(f) == "function" then register_function(f) end
  if RUN_CALLBACKS and type(f) == "function" and not cb_seen[f] then
    if #cb_queue >= MAX_CALLBACKS then metrics.callback_limit = 1; return end
    cb_seen[f] = true
    cb_queue[#cb_queue + 1] = {fn = f, args = args, n = n}
  end
end

local function queue_value(v, seen, depth)
  if type(v) == "function" then queue_fn(v); return end
  if type(v) ~= "table" or gdata[v] or depth > 4 or seen[v] then return end
  seen[v] = true
  local callback = rawget(v, "callback") or rawget(v, "Callback")
  if type(callback) == "function" then
    local value = rawget(v, "value")
    if value == nil then value = rawget(v, "Value") end
    if rawget(v, "state") ~= nil or rawget(v, "State") ~= nil then value = BRANCH_TRUE end
    if value ~= nil then queue_fn(callback, {value}, 1) end
  end
  local count = 0
  for _, child in next, v do
    count = count + 1
    if count > 100 then metrics.callback_limit = 1; break end
    queue_value(child, seen, depth + 1)
  end
end

-- ------------------------------------------------ objetos "fantasma"
local ghost_mt = {__metatable = "objeto simbolico"}
local NIL_VALUE = {}
local COLLECTION_METHODS = {GetChildren = true, GetDescendants = true, GetPlayers = true, GetTagged = true}
local function new_ghost(path, parent, key)
  local g = setmetatable({}, ghost_mt)
  gdata[g] = {path = path, parent = parent, key = key, kids = {}, values = {}}
  return g
end
local function gexpr(g) return names[g] or gdata[g].path end
local function child_path(g, k)
  if is_ident(k) then return gexpr(g) .. "." .. k end
  return gexpr(g) .. "[" .. fmt(k) .. "]"
end

ghost_mt.__index = function(g, k)
  local d = gdata[g]
  local value = d.values[k]
  if value ~= nil then
    if rawequal(value, NIL_VALUE) then return nil end
    return value
  end
  local kid = (k ~= nil) and d.kids[k] or nil
  if kid == nil then
    kid = new_ghost(child_path(g, k), g, k)
    if k ~= nil and k == k then d.kids[k] = kid end
  end
  return kid
end

ghost_mt.__newindex = function(g, k, v)
  if k == nil or k ~= k then error("indice de tabla invalido", 2) end
  metrics.assignments = metrics.assignments + 1
  gdata[g].values[k] = v == nil and NIL_VALUE or v
  emit(child_path(g, k) .. " = " .. fmt(v))
  queue_value(v, {}, 0)
end

ghost_mt.__call = function(g, ...)
  local d = gdata[g]
  local n = select("#", ...)
  local args = {...}
  -- Iteracion generalizada de Luau ya compilada por Vmify: el resultado de
  -- GetChildren/GetDescendants puede actuar directamente como iterador.
  if d.collection and n == 2 then
    local index = (type(args[2]) == "number" and args[2] or 0) + 1
    if index > 3 then return nil end
    return index, new_ghost(gexpr(g) .. "[" .. index .. "]", g, index)
  end
  local first, callee = 1, gexpr(g)
  if d.parent and n >= 1 and rawequal(args[1], d.parent) and is_ident(d.key) then
    first = 2
    callee = gexpr(d.parent) .. ":" .. d.key
  end
  for i = first, n do queue_value(args[i], {}, 0) end
  metrics.calls = metrics.calls + 1
  counters.v = counters.v + 1
  local nm = "v" .. counters.v
  -- Conservamos una expresion simbolica mas informativa para resultados de API.
  local respath = callee .. "(" .. fmt_list(args, first, n) .. ")"
  local res = new_ghost(respath)
  gdata[res].collection = COLLECTION_METHODS[d.key] or false
  names[res] = nm
  emit("local " .. nm .. " = " .. respath)
  return res
end

local function binop(op)
  return function(a, b) return new_ghost("(" .. fmt(a) .. " " .. op .. " " .. fmt(b) .. ")") end
end
ghost_mt.__add, ghost_mt.__sub, ghost_mt.__mul = binop("+"), binop("-"), binop("*")
ghost_mt.__div, ghost_mt.__mod, ghost_mt.__pow = binop("/"), binop("%"), binop("^")
ghost_mt.__idiv, ghost_mt.__concat = binop("//"), binop("..")
ghost_mt.__unm = function(a) return new_ghost("(-" .. fmt(a) .. ")") end
ghost_mt.__len = function() return 0 end
local function comparison()
  metrics.comparisons = metrics.comparisons + 1
  return BRANCH_TRUE
end
ghost_mt.__eq, ghost_mt.__lt, ghost_mt.__le = comparison, comparison, comparison
ghost_mt.__tostring = function(g) return gexpr(g) end

-- ------------------------------------------------ iteracion simbolica / metodos
-- Prometheus puede recorrer resultados de API que en un sandbox son fantasmas.
-- En lugar de devolver una tabla vacia, producimos pocos elementos simbolicos
-- acotados para que se pueda atravesar la logica de callbacks sin crear loops.
local ITER_LIMIT = 3
local function ghost_item(g, label, idx)
  local base = gexpr(g)
  return new_ghost(base .. "[" .. idx .. "]", g, idx)
end
local function symbolic_iter(g, i)
  i = i + 1
  if i > ITER_LIMIT then return nil end
  return i, ghost_item(g, "item", i)
end
local function symbolic_pairs(g)
  local i = 0
  return function()
    local k, v = symbolic_iter(g, i)
    if k then i = k; return k, v end
  end, g, 0
end
local function symbolic_ipairs(g)
  return symbolic_pairs(g)
end
local real_pairs, real_ipairs = pairs, ipairs
pairs = function(t)
  if gdata[t] then return symbolic_pairs(t) end
  return real_pairs(t)
end
ipairs = function(t)
  if gdata[t] then return symbolic_ipairs(t) end
  return real_ipairs(t)
end

-- ------------------------------------------------------------ compilar
local function compile(src, chunkname, env)
  if ssub(src, 1, 1) == "\27" then return nil, "bytecode bloqueado" end
  if setfenv_real then -- Lua 5.1 / LuaJIT
    local f, err = loadstring_real(src, chunkname)
    if not f then return nil, err end
    setfenv_real(f, env)
    return f
  end
  return load_real(src, chunkname, "t", env) -- Lua 5.2+
end

-- ------------------------------------------------------------- sandbox
local S = {}
for _, n in ipairs({"assert", "error", "ipairs", "next", "pairs",
  "pcall", "rawequal", "rawget", "rawset", "select", "setmetatable", "tonumber", "tostring",
  "type", "xpcall", "_VERSION", "math", "string", "table", "utf8", "bit32", "bit"}) do
  if type(G[n]) == "table" then
    local copy = {}
    for k, v in next, G[n] do if k ~= "dump" then copy[k] = v end end
    S[n] = copy
  elseif G[n] ~= nil then S[n] = G[n] end
end
S.getmetatable = function(v)
  if type(v) == "string" then return {__index = S.string, __metatable = "string"} end
  return getmetatable(v)
end
S.string.char = function(...)
  local s = G.string.char(...); observe(s, "string.char"); return s
end
S.table.concat = function(...)
  local s = tconcat(...); observe(s, "table.concat"); return s
end
S.rawset = function(t, k, v)
  if gdata[t] then ghost_mt.__newindex(t, k, v); return t end
  return rawset(t, k, v)
end
S.rawget = function(t, k)
  if gdata[t] then
    local v = gdata[t].values[k]
    if rawequal(v, NIL_VALUE) then return nil end
    return v
  end
  return rawget(t, k)
end
S.unpack = unpack_
S.pairs = pairs
S.ipairs = ipairs
S._G = S
-- Las bibliotecas del analizador conservan sus propias tablas.

local function blocked(name)
  return function(...)
    metrics.blocked = metrics.blocked + 1
    local args = {...}
    emit("-- BLOQUEADO: " .. name .. "(" .. fmt_list(args, 1, select("#", ...)) .. ")")
    return nil, "bloqueado por el sandbox"
  end
end

S.print = function(...)
  local args = {...}
  emit("print(" .. fmt_list(args, 1, select("#", ...)) .. ")")
end
S.warn = function(...)
  local args = {...}
  emit("warn(" .. fmt_list(args, 1, select("#", ...)) .. ")")
end

S.os = {
  time = os_time, clock = os_clock, date = os_date, difftime = os_difftime,
  getenv = function() return nil end,
  exit = function() emit("-- os.exit() invocado"); error(EXIT_TAG, 0) end,
  execute = blocked("os.execute"), remove = blocked("os.remove"), rename = blocked("os.rename"),
  tmpname = blocked("os.tmpname"), setlocale = blocked("os.setlocale"),
}
local function io_write(...)
  local args = {...}
  emit("io.write(" .. fmt_list(args, 1, select("#", ...)) .. ")")
end
local fake_out = {}
fake_out.write = function(self, ...) io_write(...); return self end
S.io = {
  open = blocked("io.open"), popen = blocked("io.popen"), lines = blocked("io.lines"),
  read = function() return nil end, write = io_write, stdout = fake_out, stderr = fake_out,
}
S.dofile, S.loadfile = blocked("dofile"), blocked("loadfile")
S.require = function(name)
  emit("-- require(" .. fmt(name) .. ")")
  return new_ghost("require(" .. fmt(name) .. ")")
end
S.debug = {traceback = d_traceback}

-- loadstring / load: guarda cada payload y lo ejecuta dentro del mismo sandbox
local payloads, payload_bytes = 0, 0
local payload_seen = {}
local function loader(chunk, name, mode, env)
  if type(chunk) == "function" then
    local pieces, size = {}, 0
    while true do
      local p = chunk()
      if p == nil or p == "" then break end
      if type(p) ~= "string" then return nil, "el lector debe devolver cadenas" end
      size = size + #p
      if size > MAX_PAYLOAD_BYTES or #pieces >= 100000 then finish("payload_limit") end
      pieces[#pieces + 1] = p
    end
    chunk = tconcat(pieces)
  end
  if type(chunk) == "table" and gdata[chunk] then -- p. ej. game:HttpGet(url)
    return new_ghost("loadstring(" .. fmt(chunk) .. ")")
  end
  if type(chunk) ~= "string" then return nil, "argumento invalido" end
  if not payload_seen[chunk] then
    if payloads >= MAX_PAYLOADS or payload_bytes + #chunk > MAX_PAYLOAD_BYTES then
      finish("payload_limit")
    end
    payloads = payloads + 1
    payload_bytes = payload_bytes + #chunk
    payload_seen[chunk] = payloads
    local pname = sformat("payloads/stage_%03d.lua", payloads)
    local pf = assert(io_open(OUTDIR .. "/" .. pname, "wb"))
    pf:write(chunk); pf:close()
    metrics.payloads = payloads
  end
  local pname = sformat("payloads/stage_%03d.lua", payload_seen[chunk])
  emit(sformat("-- loadstring/load: %d bytes -> %s", #chunk, pname))
  if ssub(chunk, 1, 1) == "\27" then
    emit("-- (bytecode precompilado: bloqueado)")
    return nil, "bytecode bloqueado"
  end
  if mode and not mode:find("t", 1, true) then return nil, "solo se admite texto" end
  local f, err = compile(chunk, "=stage" .. payload_seen[chunk], (type(env) == "table") and env or S)
  if not f then
    emit("-- error de sintaxis en el payload: " .. tostring(err))
    return nil, err
  end
  return f
end
S.load = loader
S.loadstring = function(chunk, name) return loader(chunk, name, "t", S) end

-- getfenv / setfenv (5.1): nunca devuelven ni modifican el entorno real
if setfenv_real then
  S.getfenv = function(f)
    if f == nil then f = 1 end
    if f == 0 then return S end
    local lvl = (type(f) == "number") and (f + 1) or f
    local e = getfenv_real(lvl)
    if e == G or e == nil then return S end
    return e
  end
  S.setfenv = function(f, t)
    local lvl = (type(f) == "number") and (f + 1) or f
    local cur = getfenv_real(lvl)
    if cur == G or cur == nil then error("setfenv: destino no permitido", 2) end
    return setfenv_real(lvl, t)
  end
end

S.newproxy = newproxy_real or function(arg1) -- reemplazo aproximado en Lua 5.2+
  local t = {}
  if arg1 == true then
    setmetatable(t, {})
  elseif type(arg1) == "table" then
    local mt = getmetatable(arg1)
    if mt then setmetatable(t, mt) end
  end
  return t
end

-- limite de CPU (tambien dentro de corrutinas)
local T0 = os_clock()
local cb_deadline = nil
local function hookfn()
  local now = os_clock()
  if now - T0 > CPU_LIMIT then
    finish("timeout", "limite de CPU")
  end
  if cb_deadline and now > cb_deadline then error(CB_TIMEOUT, 0) end
end

local co_s = {}
for k, v in pairs(coroutine) do co_s[k] = v end
co_s.create = function(f)
  local c = co_create(f)
  if d_sethook then d_sethook(c, hookfn, "", 100000) end
  return c
end
local function co_unwrap(ok, ...)
  if not ok then error((...), 0) end
  return ...
end
co_s.wrap = function(f)
  local c = co_s.create(f)
  return function(...) return co_unwrap(co_resume(c, ...)) end
end
S.coroutine = co_s

-- API tipo Roblox / executor: tareas diferidas, tiempo, typeof...
local function spawn_fn(f, ...)
  queue_fn(f, {...}, select("#", ...))
  return new_ghost("thread")
end
S.spawn = spawn_fn
S.delay = function(_, f, ...) return spawn_fn(f, ...) end
S.wait = function()
  wait_count = wait_count + 1
  if wait_count > MAX_WAITS then error(WAIT_LIMIT, 0) end
  return 0.03
end
S.tick = function() return os_time() + (os_clock() % 1) end
S.time = os_clock
S.typeof = function(v) if gdata[v] then return "Instance" end return type(v) end
S.task = {wait = S.wait, spawn = spawn_fn, defer = spawn_fn, delay = S.delay, cancel = function() end}
S.getgenv = function() return S end
S.getrenv = S.getgenv
S.identifyexecutor = function() return "prometheus_devirt", "1.0" end
S.getexecutorname = S.identifyexecutor

local HOST = {}
for w in sgmatch([[game workspace script Instance Enum Vector2 Vector3 Vector2int16 Vector3int16 CFrame
  Color3 ColorSequence ColorSequenceKeypoint NumberSequence NumberSequenceKeypoint NumberRange UDim UDim2
  Rect Ray Region3 TweenInfo BrickColor Random PhysicalProperties Faces Axes DateTime Font OverlapParams
  RaycastParams shared plugin settings UserSettings stats version getreg getgc getconnections
  hookfunction hookmetamethod newcclosure checkcaller islclosure iscclosure getrawmetatable
  setrawmetatable setreadonly isreadonly make_writeable make_readonly syn http request http_request
  fluxus KRNL_LOADED setclipboard toclipboard writefile readfile appendfile isfile isfolder makefolder
  listfiles delfile delfolder queue_on_teleport queueonteleport gethui cloneref clonefunction
  fireclickdetector firetouchinterest fireproximityprompt setthreadidentity getthreadidentity
  setidentity getidentity Drawing messagebox rconsoleprint rconsolename printconsole getscripts
  getloadedmodules getnilinstances getinstances saveinstance decompile getcustomasset]], "%S+") do
  HOST[w] = true
end
for w in sgmatch(EXTRA_GHOSTS, "[^,]+") do HOST[w] = true end

local NEVER_GHOST = {_ENV = true, jit = true, bit = true, bit32 = true, utf8 = true, unpack = true,
  loadstring = true, setfenv = true, getfenv = true, newproxy = true, gcinfo = true, module = true,
  ffi = true, package = true, debug = true}
local root_ghosts = {}

setmetatable(S, {
  __index = function(_, k)
    if type(k) ~= "string" then return nil end
    if HOST[k] or (GHOST_ALL and not NEVER_GHOST[k]) then
      local g = root_ghosts[k]
      if not g then
        g = new_ghost(k)
        root_ghosts[k] = g
      end
      return g
    end
    return nil
  end,
  __newindex = function(t, k, v)
    rawset(t, k, v)
    local nm = is_ident(k) and k or ("_G[" .. fmt(k) .. "]")
    emit(nm .. " = " .. fmt(v))
    queue_value(v, {}, 0)
  end,
})

-- --------------------------------------------- callbacks y descifrado
local function run_callbacks()
  local per_cb = CPU_LIMIT / 10
  if per_cb < 1 then per_cb = 1 end
  local i = 1
  while i <= #cb_queue and i <= MAX_CALLBACKS do
    metrics.callbacks = metrics.callbacks + 1
    local item = cb_queue[i]
    local nm = register_function(item.fn)
    context = nm
    functionf:write("status\t", nm, "\trunning\n")
    emit("-- callback sintetico: argumentos/orden aproximados")
    if item.args then
      emit("-- argumentos observados: " .. fmt_list(item.args, 1, item.n))
    end
    wait_count = 0
    cb_deadline = os_clock() + per_cb
    local function capture_returns(...)
      local values, n = {...}, select("#", ...)
      for index = 1, n do queue_value(values[index], {}, 0) end
      emit("return " .. fmt_list(values, 1, n))
    end
    local ok, err = pcall(function()
      if item.args then return capture_returns(item.fn(unpack_(item.args, 1, item.n))) end
      return capture_returns(item.fn(new_ghost("arg1"), new_ghost("arg2")))
    end)
    cb_deadline = nil
    if not ok and not rawequal(err, EXIT_TAG) then
      metrics.callback_errors = metrics.callback_errors + 1
      if rawequal(err, WAIT_LIMIT) then
        metrics.wait_limits = metrics.wait_limits + 1
        emit("-- bucle interrumpido: limite de wait/task.wait")
      elseif rawequal(err, CB_TIMEOUT) then
        metrics.callback_timeouts = metrics.callback_timeouts + 1
        emit("-- (funcion cortada por tiempo)")
      else
        emit("-- error en la funcion: " .. (type(err) == "string" and err or fmt(err)))
      end
    end
    function_records[nm].status = ok and "observed" or (rawequal(err, WAIT_LIMIT) and "wait_limit" or "error")
    functionf:write("status\t", nm, "\t", function_records[nm].status, "\n")
    context = "main"
    i = i + 1
  end
end

local function dump_strings()
  local out = io_open(OUTDIR .. "/decrypted.txt", "wb")
  if not out then return 0 end
  local count = 0
  local st = rawget(S, "STRINGS")
  -- No ejecutar descifradores adicionales al finalizar: solo observar la cache.

  if type(st) == "table" then
    local mt = getmetatable(st)
    local store = type(mt) == "table" and rawget(mt, "__index") or nil
    if type(store) == "table" then
      local keys = {}
      for k, v in next, store do
        if type(v) == "string" then keys[#keys + 1] = k end
      end
      pcall(tsort, keys)
      for _, k in ipairs(keys) do
        local value = rawget(store, k)
        observe(value, "decrypt_cache")
        out:write(fmt(k), "\t", qstr(value), "\n")
        count = count + 1
      end
    end
  end
  out:close()
  return count
end

function finish(status, errmsg, tb)
  if finished then return end
  if not finishing and (status == "ok" or status == "error") then
    finishing = true
    if RUN_CALLBACKS then
      local cb_ok = pcall(run_callbacks)
      if not cb_ok then metrics.callback_errors = metrics.callback_errors + 1 end
    end
    pcall(dump_strings)
  end
  if status == "ok" and (metrics.callback_errors > 0 or metrics.callback_limit > 0) then
    status = "partial"
    errmsg = "callbacks fallidos o limite de callbacks alcanzado"
  end
  finished = true
  if d_sethook then d_sethook() end
  dynamic_file:close()
  eventf:close()
  functionf:close()
  local mf = assert(io_open(OUTDIR .. "/metrics.txt", "wb"))
  for k, v in next, metrics do mf:write(k, "\t", tostring(v), "\n") end
  mf:close()
  logf:write("-- fin de la traza: ", status, "\n")
  logf:close()
  local msg = (sgsub(type(errmsg) == "string" and errmsg or "", "[\r\n]", " "))
  local sf = io_open(OUTDIR .. "/status.txt", "wb")
  if sf then
    sf:write(status, "\n", msg, "\n", tostring(tb or ""), "\n")
    sf:close()
  end
  os_exit(0)
end

-- ------------------------------------------------------------ ejecucion
local src = readfile(TARGET)
if not src then
  io_stderr:write("no se pudo leer el archivo objetivo\n")
  os_exit(4)
end
src = (sgsub(src, "^\239\187\191", ""))
src = (sgsub(src, "^#[^\n]*", "--"))

if d_sethook then d_sethook(hookfn, "", 100000) end

emit("-- prometheus_devirt: traza reconstruida a partir de la ejecucion (NO es el codigo fuente original)")
emit("-- origen: " .. tostring(TARGET))
emit("-- vN = objeto devuelto por una llamada; fnN = funcion; ver reconstructed.lua y functions.json")
emit("")

local chunk, cerr = compile(src, "=" .. (smatch(TARGET, "[^/\\]+$") or "objetivo"), S)
if not chunk then
  emit("-- ERROR de sintaxis (si es Luau, prueba otro runtime): " .. tostring(cerr))
  finish("syntax_error", cerr)
end

local function run_chunk()
  local function returned(...)
    local values, n = {...}, select("#", ...)
    for index = 1, n do queue_value(values[index], {}, 0) end
    emit("return " .. fmt_list(values, 1, n))
  end
  returned(chunk())
end
local ok, err = xpcall(run_chunk, function(m)
  if rawequal(m, EXIT_TAG) then return m end
  if rawequal(m, WAIT_LIMIT) then return {msg = "limite de wait/task.wait en bloque principal"} end
  return {msg = (type(m) == "string") and m or fmt(m), tb = d_traceback and d_traceback("", 2) or ""}
end)

if ok or rawequal(err, EXIT_TAG) then
  finish("ok")
else
  local msg = (type(err) == "table" and err.msg) or tostring(err)
  emit("-- ERROR: " .. msg)
  finish("error", msg, type(err) == "table" and err.tb or "")
end
'''

# ---------------------------------------------------------------------------
# Analisis estatico: lexer de literales; nunca evalua Lua ni Python.
# ---------------------------------------------------------------------------
_SIMPLE_ESC = dict(zip(b"abfnrtv", (7, 8, 12, 10, 13, 9, 11)))
_SIMPLE_ESC.update({92: 92, 34: 34, 39: 39})
_LONG_OPEN = re.compile(rb"\[(=*)\[")
_WORD = re.compile(rb"[a-zA-Z_][a-zA-Z_0-9]*|[0-9]+")
_URL_RE = re.compile(rb"https?://[^\s\"'<>\\\x00-\x1f]+", re.I)
MAX_INPUT = 16 * 1024 * 1024


class LuaLexError(ValueError):
    """Literal invalido; el desplazamiento esta expresado en bytes."""


def _read_short(src: bytes, i: int):
    q, j, out = src[i], i + 1, bytearray()
    while j < len(src):
        b = src[j]
        if b == q:
            return bytes(out), j + 1
        if b in (10, 13):
            raise LuaLexError(f"salto de linea sin escapar en byte {j}")
        if b != 92:
            out.append(b)
            j += 1
            continue
        j += 1
        if j == len(src):
            break
        e = src[j]
        if e in _SIMPLE_ESC:
            out.append(_SIMPLE_ESC[e])
            j += 1
        elif 48 <= e <= 57:
            match = re.match(rb"[0-9]{1,3}", src[j:j + 3])
            value = int(match.group())
            if value > 255:
                raise LuaLexError(f"escape decimal fuera de 0..255 en byte {j}")
            out.append(value)
            j += len(match.group())
        elif e == ord("x"):
            digits = src[j + 1:j + 3]
            if not re.fullmatch(rb"[0-9a-fA-F]{2}", digits):
                raise LuaLexError(f"escape hexadecimal invalido en byte {j}")
            out.append(int(digits, 16))
            j += 3
        elif e == ord("u"):
            match = re.match(rb"u\{([0-9A-Fa-f]{1,8})\}", src[j:j + 12])
            if not match:
                raise LuaLexError(f"escape Unicode invalido en byte {j}")
            try:
                out.extend(chr(int(match.group(1), 16)).encode("utf-8"))
            except (ValueError, UnicodeError) as exc:
                raise LuaLexError(f"Unicode invalido en byte {j}") from exc
            j += match.end()
        elif e == ord("z"):
            j += 1
            while j < len(src) and src[j] in b" \t\n\r\v\f":
                j += 1
        elif e in (10, 13):
            out.append(10)
            j += 1
            if j < len(src) and src[j] in (10, 13) and src[j] != e:
                j += 1
        else:
            # Lua 5.1 permite escapes no reconocidos y elimina la barra.
            out.append(e)
            j += 1
    raise LuaLexError(f"cadena sin cerrar en byte {i}")


def _read_long(src: bytes, match: re.Match):
    close = b"]" + match.group(1) + b"]"
    end = src.find(close, match.end())
    if end < 0:
        raise LuaLexError(f"literal/comentario largo sin cerrar en byte {match.start()}")
    body = re.sub(rb"\r\n|\n\r|\r", b"\n", src[match.end():end])
    if body.startswith(b"\n"):
        body = body[1:]
    return body, end + len(close)


@dataclass(frozen=True)
class Token:
    kind: str
    start: int
    end: int
    value: bytes


def tokenize(src: bytes):
    """Tokens suficientes para extraer literales y llamadas, sin interpretar expresiones."""
    i = 3 if src.startswith(b"\xef\xbb\xbf") else 0
    if src[i:i + 1] == b"#":
        line = re.search(rb"[\r\n]", src[i:])
        i = len(src) if line is None else i + line.start()
    while i < len(src):
        if src[i] in b" \t\r\n\v\f":
            i += 1
            continue
        start = i
        if src[i:i + 2] == b"--":
            match = _LONG_OPEN.match(src, i + 2)
            if match:
                _, i = _read_long(src, match)
            else:
                line = re.search(rb"[\r\n]", src[i + 2:])
                i = len(src) if line is None else i + 2 + line.start()
            continue
        if src[i] in (34, 39):
            value, i = _read_short(src, i)
            yield Token("string", start, i, value)
            continue
        match = _LONG_OPEN.match(src, i)
        if match:
            value, i = _read_long(src, match)
            yield Token("string", start, i, value)
            continue
        match = _WORD.match(src, i)
        if match:
            value = match.group()
            i += len(value)
            yield Token("name" if value[:1].isalpha() or value[:1] == b"_" else "number", start, i, value)
        else:
            i += 1
            yield Token("symbol", start, i, src[start:i])


def index_source_functions(src: bytes, salida: Path):
    """Indexa spans exactos, incluidas funciones nunca alcanzadas en la ejecucion.

    Solo reconoce bloques Lua; no interpreta expresiones ni supone que las
    funciones extraidas puedan ejecutarse sin sus variables externas.
    """
    tokens = list(tokenize(src))
    stack, records = [], []
    for i, token in enumerate(tokens):
        if token.kind != "name":
            continue
        word = token.value
        if word in (b"function", b"if", b"for", b"while", b"do", b"repeat"):
            if word == b"do" and stack and stack[-1]["await_do"]:
                stack[-1]["await_do"] = False
                continue
            frame = {"kind": word, "start": token.start, "await_do": word in (b"for", b"while")}
            if word == b"function":
                parent = next((f["id"] for f in reversed(stack) if f["kind"] == b"function"), None)
                name = f"source_fn{len(records) + 1:04d}"
                frame["id"] = name
                record = {"id": name, "parent": parent, "start_byte": token.start,
                          "end_byte": None, "file": None}
                # Cabecera function [nombre] (parametros); no buscar mas alla del cierre.
                j = i + 1
                while j < len(tokens) and tokens[j].value != b"(":
                    if tokens[j].kind != "name" and tokens[j].value not in (b".", b":"):
                        break
                    j += 1
                if j < len(tokens) and tokens[j].value == b"(":
                    k = j + 1
                    while k < len(tokens) and tokens[k].value != b")":
                        k += 1
                    if k < len(tokens):
                        record["parameters_text"] = src[tokens[j].end:tokens[k].start].decode("utf-8", "replace")
                records.append(record)
                frame["record"] = record
            stack.append(frame)
        elif word in (b"end", b"until"):
            if not stack or (word == b"until") != (stack[-1]["kind"] == b"repeat"):
                return {"status": "unsupported_structure", "functions": records}
            frame = stack.pop()
            if frame["kind"] == b"function":
                frame["record"]["end_byte"] = token.end
    if stack:
        return {"status": "incomplete_structure", "functions": records}
    # Los spans se guardan en el indice y una unica copia conserva todos los
    # cuerpos, evitando duplicar funciones anidadas de forma cuadratica.
    (salida / "source_functions.lua").write_bytes(src)
    for record in records:
        record["file"] = "source_functions.lua"
    return {"status": "indexed", "source_recovered": False, "functions": records}


def reconstruct_functions(root: Path):
    """Genera cuerpos por funcion a partir de eventos, sin mezclar pasadas."""
    records, contexts = {}, {"main": []}
    path = root / "functions.tsv"
    if path.exists():
        for line in path.read_text(encoding="ascii", errors="replace").splitlines():
            fields = line.split("\t")
            try:
                kind, name = fields[:2]
                if not re.fullmatch(r"fn[1-9][0-9]*", name):
                    continue
                if kind == "register" and len(fields) == 7:
                    records[name] = {"id": name, "status": "not_executed",
                        "source": bytes.fromhex(fields[2]).decode("utf-8", "replace"),
                        "line": int(fields[3]), "last_line": int(fields[4]),
                        "nparams": int(fields[5]), "isvararg": fields[6] == "true", "upvalues": []}
                elif kind == "status" and len(fields) == 3 and name in records:
                    records[name]["status"] = fields[2]
                elif kind == "upvalue" and len(fields) == 5 and name in records:
                    records[name]["upvalues"].append({"name": bytes.fromhex(fields[2]).decode("utf-8", "replace"),
                        "type": fields[3], "value_hex": fields[4]})
            except (ValueError, IndexError):
                continue  # Un proceso terminado externamente puede dejar una linea truncada.
    path = root / "trace_events.hex"
    if path.exists():
        with path.open("rb") as stream:
            for line in stream:
                context, sep, data = line.rstrip(b"\r\n").partition(b"\t")
                if not sep:
                    continue
                try:
                    name = context.decode("ascii")
                    if name != "main" and name not in records:
                        continue
                    contexts.setdefault(name, []).append(bytes.fromhex(data.decode("ascii")))
                except (ValueError, UnicodeError):
                    continue

    def rewrite(line):
        # Tablas compartidas para referencias entre callbacks y para no superar
        # los 200 locales de Lua. El lexer impide sustituir dentro de cadenas.
        line = re.sub(rb"^local (v[0-9]+) =", rb"\1 =", line)
        result, cursor = bytearray(), 0
        try:
            for token in tokenize(line):
                if token.kind == "name" and re.fullmatch(rb"(?:v|fn)[1-9][0-9]*", token.value):
                    prefix = b"values." if token.value.startswith(b"v") else b"functions."
                    result.extend(line[cursor:token.start])
                    result.extend(prefix + token.value)
                    cursor = token.end
        except LuaLexError:
            return b"-- evento no representable: " + repr(line).encode("ascii")
        result.extend(line[cursor:])
        return bytes(result)

    destination = root / "functions"
    destination.mkdir(exist_ok=True)
    header = (b"-- Reconstruccion PARCIAL de efectos observados; no es codigo equivalente.\n"
              b"-- Las ramas, argumentos, retornos y valores dependen de la simulacion.\n"
              b"local values, functions = {}, {}\n")
    chunks = [header]
    for name, record in records.items():
        body = contexts.get(name, [])
        if record["status"] == "running":
            record["status"] = "interrupted"
        record["body_observed"] = record["status"] == "observed"
        record["complete"] = False
        record["file"] = f"functions/{name}.lua"
        definition = [f"functions.{name} = function(arg1, arg2, ...)\n".encode(),
                      f"  -- estado: {record['status']}; firma sintetica\n".encode()]
        if not body:
            definition.append(b"  -- Cuerpo no observado; consultar source_functions.lua y upvalues.\n")
        for line in body:
            definition.append(b"  " + rewrite(line) + b"\n")
        definition.append(b"end\n")
        chunk = b"".join(definition)
        (destination / f"{name}.lua").write_bytes(b"-- Fragmento de reconstructed.lua; usa sus tablas values/functions.\n" + chunk)
        chunks.append(chunk)
    chunks.append(b"\n-- Efectos del bloque principal\n")
    chunks.extend(rewrite(line) + b"\n" for line in contexts["main"])
    (root / "reconstructed.lua").write_bytes(b"".join(chunks))
    result = {"full_devirtualization": False, "functions": list(records.values()),
              "observed": sum(r["body_observed"] for r in records.values()), "total": len(records)}
    (root / "functions.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def scan_strings(src: bytes) -> list[bytes]:
    return [t.value for t in tokenize(src) if t.kind == "string"]


def extraer_pares(src: bytes, limite: int = 50000):
    """Solo llamadas DECRYPT literales; ignora cadenas, comentarios y miembros."""
    from collections import deque
    window, pairs, seen = deque(maxlen=7), [], set()
    if limite <= 0:
        return pairs
    for token in tokenize(src):
        window.append(token)
        if len(window) < 6:
            continue
        ts = list(window)[-6:]
        if (ts[0].kind == "name" and ts[0].value == b"DECRYPT"
                and ts[1].value == b"(" and ts[2].kind == "string"
                and ts[3].value == b"," and ts[4].kind == "number"
                and len(ts[4].value) <= 15 and ts[5].value == b")"
                and not (len(window) == 7 and window[0].value in (b".", b":"))):
            pair = (ts[2].value, int(ts[4].value))
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
                if len(pairs) >= limite:
                    break
    return pairs


def legible(blob: bytes):
    if len(blob) < 4:
        return None
    try:
        value = blob.decode("utf-8")
    except UnicodeDecodeError:
        value = blob.decode("latin-1")
        valid = sum(32 <= b < 127 or b in (9, 10, 13) for b in blob)
    else:
        valid = sum(ch.isprintable() or ch in "\n\r\t" for ch in value)
    return value if valid / len(value) >= 0.9 else None


def fingerprint(src: bytes) -> list[str]:
    hints = []
    for word, label in ((b"newproxy", "newproxy: compatible con Vmify, no concluyente"),
                        (b"getfenv", "getfenv: API Lua 5.1"),
                        (b"Prometheus Obfuscator", "marca Prometheus")):
        if word in src:
            hints.append(label)
    return hints


def lua_literal(blob: bytes) -> str:
    """Literal sin perdida de bytes, compatible con Lua 5.1 y superior."""
    return '"' + ''.join(chr(b) if 32 <= b < 127 and b not in (34, 92)
                         else f"\\{b:03d}" for b in blob) + '"'


def minimal_env():
    return {k: v for k, v in os.environ.items() if k.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")}


def find_lua(preferido: str | None):
    candidates = [preferido] if preferido else ["luajit", "lua5.1", "lua51", "lua", "lua5.4", "lua5.3", "lua5.2"]
    for candidate in candidates:
        exe = shutil.which(candidate)
        if not exe:
            continue
        exe = str(Path(exe).resolve())
        try:
            result = subprocess.run([exe, "-e", "print(_VERSION, jit and jit.version or '')"],
                                    env=minimal_env(), capture_output=True, text=True,
                                    errors="replace", timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and re.match(r"Lua 5\.[1-4]\b", result.stdout):
            return exe, result.stdout.strip().replace("\t", " ")
    return None, ""


@dataclass
class PassResult:
    name: str
    status: str
    message: str
    returncode: int | None
    wall_seconds: float
    timed_out: bool
    ghost_all: bool
    branch_policy: str
    callbacks_enabled: bool
    metrics: dict
    stderr: str


def leer_estado(salida: Path):
    p = salida / "status.txt"
    if not p.exists():
        return "desconocido", "", ""
    parts = (p.read_text(encoding="utf-8", errors="replace") + "\n\n").split("\n", 2)
    return parts[0].strip(), parts[1].strip(), parts[2].strip()


def _resource_limiter(args):
    import resource

    def apply():
        cpu = math.ceil(args.timeout) + 1
        for name, value in (("RLIMIT_CPU", cpu), ("RLIMIT_AS", args.memory_mb * 1024 * 1024),
                            ("RLIMIT_FSIZE", 40 * 1024 * 1024), ("RLIMIT_CORE", 0)):
            if hasattr(resource, name):
                key = getattr(resource, name)
                _, hard = resource.getrlimit(key)
                if hard != resource.RLIM_INFINITY:
                    value = min(value, hard)
                resource.setrlimit(key, (value, value))
    return apply


def ejecutar(lua: str, objetivo: Path, salida: Path, args) -> PassResult:
    """Cada pasada dispone de proceso, entorno, limites y carpeta independientes."""
    (salida / "payloads").mkdir(parents=True)
    (salida / "harness.lua").write_text(HARNESS_LUA, encoding="utf-8")
    cmd = [lua, str((salida / "harness.lua").resolve()), str(objetivo.resolve()), str(salida.resolve()),
           str(args.timeout), args.ghost, "1" if args.ghost_all else "0", "-",
           "0" if args.no_callbacks else "1", args.branch_policy, str(args.max_callbacks),
           str(args.payload_mb * 1024 * 1024), str(args.max_waits)]
    started, timed_out, returncode, launch_error = time.monotonic(), False, None, ""
    kwargs = {}
    if os.name == "posix":
        kwargs = {"start_new_session": True, "preexec_fn": _resource_limiter(args)}
    with (salida / "stdout.log").open("wb") as stdout, (salida / "stderr.log").open("wb") as stderr:
        try:
            proc = subprocess.Popen(cmd, cwd=salida, env=minimal_env(), stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, **kwargs)
            try:
                returncode = proc.wait(timeout=args.wall_timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                timed_out = isinstance(exc, subprocess.TimeoutExpired)
                try:
                    if os.name == "posix":
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                returncode = proc.wait()
                if not timed_out:
                    raise
        except (OSError, subprocess.SubprocessError) as exc:
            launch_error = str(exc)
    status, message, _ = leer_estado(salida)
    with (salida / "stderr.log").open("rb") as stream:
        stderr_text = stream.read(8192).decode("utf-8", "replace")
    metrics = {}
    metrics_file = salida / "metrics.txt"
    if metrics_file.exists():
        for line in metrics_file.read_text().splitlines():
            key, value = line.split("\t", 1)
            metrics[key] = int(value)
    if timed_out:
        status, message = "wall_timeout", "limite de tiempo real"
    elif launch_error:
        status, message = "launch_error", launch_error
    elif returncode != 0:
        status, message = "process_error", f"interprete termino con codigo {returncode}"
    elif status not in ESTADOS:
        status, message = "protocol_error", "el arnes no produjo un estado reconocido"
    elif status == "ok" and (metrics.get("callback_errors") or metrics.get("callback_limit")):
        status, message = "partial", "callbacks fallidos o limite de callbacks alcanzado"
    reconstruct_functions(salida)
    result = PassResult(salida.name, status, message, returncode,
                        round(time.monotonic() - started, 3), timed_out, args.ghost_all,
                        args.branch_policy, not args.no_callbacks, metrics, stderr_text)
    (salida / "result.json").write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n")
    return result


def ejecutar_multi(lua: str, objetivo: Path, salida: Path, args):
    modes = [(args.ghost_all, args.branch_policy)]
    if args.multi:
        modes += [(args.ghost_all, "true" if args.branch_policy == "false" else "false"),
                  (True, "false"), (True, "true")]
    results = []
    for idx, (ghost_all, branch) in enumerate(dict.fromkeys(modes)):
        options = SimpleNamespace(**vars(args))
        options.ghost_all, options.branch_policy = ghost_all, branch
        name = f"pass_{idx + 1:02d}"
        print(f"[*] {name}: ghost_all={ghost_all}, comparaciones={branch}, CPU={args.timeout}s", flush=True)
        results.append(ejecutar(lua, objetivo, salida / name, options))
    # La finalizacion tiene prioridad sobre el volumen (un bucle no es mas cobertura).
    rank = {"ok": 4, "partial": 3, "error": 2}
    best = max(results, key=lambda r: (rank.get(r.status, 0),
                                      r.metrics.get("payloads", 0), r.metrics.get("calls", 0)))
    for filename in ("devirt.lua", "reconstructed.lua", "functions.json", "decrypted.txt", "status.txt"):
        source = salida / best.name / filename
        if source.exists():
            shutil.copyfile(source, salida / filename)
    shutil.copytree(salida / best.name / "functions", salida / "functions")
    return results, best.name


ESTADOS = {
    "ok": "ejecucion terminada; no implica recuperacion completa",
    "partial": "traza parcial: callbacks incompletos",
    "error": "error Lua; traza parcial",
    "syntax_error": "sintaxis no admitida por el interprete",
    "timeout": "limite de CPU alcanzado",
    "wall_timeout": "limite de tiempo real alcanzado",
    "log_limit": "limite de traza alcanzado",
    "payload_limit": "limite de payloads alcanzado",
    "launch_error": "no se pudo iniciar el interprete",
    "process_error": "el proceso fallo o fue terminado",
    "protocol_error": "salida incompleta del arnes",
}


def collect_artifacts(salida: Path, results):
    """Conserva bytes, deduplica por contenido y registra todas las procedencias."""
    payloads, dynamic = {}, {}
    destination = salida / "payloads"
    destination.mkdir()
    for result in results:
        root = salida / result.name
        for path in sorted((root / "payloads").glob("stage_*.lua")):
            blob = path.read_bytes()
            digest = hashlib.sha256(blob).hexdigest()
            if digest not in payloads:
                filename = f"{digest}.lua"
                (destination / filename).write_bytes(blob)
                payloads[digest] = {"file": f"payloads/{filename}", "sha256": digest,
                                    "bytes": len(blob), "bytecode": blob.startswith(b"\x1b"), "origins": []}
            payloads[digest]["origins"].append(str(path.relative_to(salida)))
        path = root / "dynamic_strings.hex"
        if path.exists():
            for line in path.read_bytes().splitlines():
                origin, sep, encoded = line.partition(b"\t")
                if not sep:
                    continue
                try:
                    blob = bytes.fromhex(encoded.decode("ascii"))
                except (ValueError, UnicodeError):
                    continue  # La ultima linea puede estar cortada por un limite externo.
                dynamic.setdefault(blob, set()).add(f"{result.name}:{origin.decode('ascii', 'replace')}")
    records = [{"hex": blob.hex(), "text": legible(blob), "origins": sorted(origins)}
               for blob, origins in dynamic.items()]
    (salida / "dynamic_strings.json").write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return list(payloads.values()), list(dynamic)


def escribir_strings(salida: Path, estaticas, dinamicas, extra_bytes=()):
    groups = [("Literales estaticos", estaticas), ("Cadenas observadas (pueden seguir cifradas)", dinamicas)]
    urls = sorted({m.group().decode("latin-1") for blob in [*estaticas, *dinamicas, *extra_bytes]
                   for m in _URL_RE.finditer(blob)})
    with (salida / "strings.txt").open("w", encoding="utf-8") as stream:
        for label, blobs in groups:
            values = list(dict.fromkeys(s for s in map(legible, blobs) if s is not None))
            stream.write(f"# {label}: {len(values)}\n")
            for value in values:
                stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.write(f"# URLs: {len(urls)}\n")
        stream.write("\n".join(urls) + "\n")
    return urls


def positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("debe ser un entero positivo") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("debe ser un entero positivo")
    return number


def parser():
    ap = argparse.ArgumentParser(description="Analisis dinamico de Prometheus: trazas y payloads; no garantiza desvirtualizacion completa.")
    ap.add_argument("archivo", help="archivo Lua (maximo 16 MiB)")
    ap.add_argument("-o", "--salida", help="carpeta nueva o vacia; nunca sobreescribe resultados")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--lua", help="ruta o nombre de Lua 5.1-5.4 / LuaJIT")
    ap.add_argument("--timeout", type=positive_int, default=20, help="segundos de CPU por pasada")
    ap.add_argument("--wall-timeout", type=positive_int, help="segundos reales por pasada (defecto: CPU + 5)")
    ap.add_argument("--memory-mb", type=positive_int, default=512, help="limite de memoria POSIX en MiB")
    ap.add_argument("--payload-mb", type=positive_int, default=16, help="bytes de payloads por pasada, en MiB")
    ap.add_argument("--max-waits", type=positive_int, default=3, help="maximo de wait/task.wait por bloque principal o callback")
    ap.add_argument("--max-callbacks", type=positive_int, default=100)
    ap.add_argument("--ghost", default="", help="globales a simular separados por coma")
    ap.add_argument("--ghost-all", action="store_true", help="simular globales desconocidos (altera el flujo)")
    ap.add_argument("--branch-policy", choices=("false", "true"), default="false", help="resultado sintetico de comparaciones entre fantasmas")
    ap.add_argument("--multi", action="store_true", help="hasta cuatro modelos de ejecucion; respeta limites y --no-callbacks")
    ap.add_argument("--no-callbacks", action="store_true")
    ap.add_argument("--desvirtualizar", action="store_true", help="eliminar un dispatcher Vmify numerico mediante luaparser (opcional)")
    ap.add_argument("--retirar-antitamper", action="store_true", help="neutralizar validacion final antitamper reconocida; implica --desvirtualizar")
    ap.add_argument("--perfil-cutgrass", action="store_true", help="descifrar cadenas y retirar antitamper solo en la muestra CutGrass exacta; implica --desvirtualizar")
    ap.add_argument("--solo-estatico", action="store_true", help="no iniciar ningun interprete")
    ap.add_argument("-y", "--yes", action="store_true", help="aceptar ejecucion sin pregunta interactiva")
    return ap


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    args.wall_timeout = args.wall_timeout or args.timeout + 5
    ghosts = [g for g in re.split(r"[,\s]+", args.ghost) if g]
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", g) for g in ghosts):
        print("[!] --ghost contiene un nombre no valido", file=sys.stderr)
        return 2
    args.ghost = ",".join(dict.fromkeys(ghosts))
    objetivo = Path(args.archivo).resolve()
    salida = Path(args.salida).resolve() if args.salida else objetivo.with_name(objetivo.stem + "_devirt")
    if not objetivo.is_file():
        print(f"[!] No existe el archivo: {objetivo}", file=sys.stderr)
        return 2
    if objetivo.stat().st_size > MAX_INPUT:
        print("[!] El archivo supera 16 MiB", file=sys.stderr)
        return 2
    if salida.exists() and (not salida.is_dir() or any(salida.iterdir())):
        print("[!] La salida debe ser una carpeta nueva o vacia; usa otra ruta con -o.", file=sys.stderr)
        return 2
    with objetivo.open("rb") as source:
        src = source.read(MAX_INPUT + 1)
    if len(src) > MAX_INPUT:
        print("[!] El archivo supera 16 MiB", file=sys.stderr)
        return 2
    salida.mkdir(parents=True, exist_ok=True)
    with (salida / ".prometheus-run").open("x", encoding="ascii") as marker:
        marker.write(__version__ + "\n")
    static, lex_error = [], None
    normalized = bytearray()
    cursor = 0
    try:
        for token in tokenize(src):
            if token.kind == "string":
                static.append(token.value)
                normalized.extend(src[cursor:token.start])
                normalized.extend(lua_literal(token.value).encode("ascii"))
                cursor = token.end
    except LuaLexError as exc:
        lex_error = str(exc)
    else:
        normalized.extend(src[cursor:])
        (salida / "normalized.lua").write_bytes(normalized)
    report = {"version": __version__, "input": str(objetivo), "input_sha256": hashlib.sha256(src).hexdigest(),
              "mode": "static" if args.solo_estatico else "dynamic", "full_devirtualization": False,
              "source_recovered": False, "coverage": "unknown", "fingerprint": fingerprint(src),
              "static_literals": len(static), "static_error": lex_error,
              "limits": {k: getattr(args, k) for k in ("timeout", "wall_timeout", "memory_mb", "payload_mb", "max_callbacks", "max_waits")},
              "os_resource_limits": os.name == "posix", "passes": [], "payloads": [],
              "limitations": ["No reconstruye el CFG ni elimina Vmify.",
                              "Los fantasmas son valores verdaderos en condiciones if; no se exploran todas las ramas.",
                              "APIs, comparaciones y callbacks simulados pueden cambiar el comportamiento.",
                              "normalized.lua solo normaliza literales (escapes Lua 5.2+ incluidos).",
                              "El entorno Lua instrumentado no es una frontera de seguridad del sistema operativo."]}
    if not lex_error:
        source_index = index_source_functions(src, salida)
        (salida / "source_functions.json").write_text(json.dumps(source_index, indent=2) + "\n", encoding="utf-8")
        report["source_functions"] = {"status": source_index["status"], "count": len(source_index["functions"]),
                                      "index": "source_functions.json"}
    vm_failed = False
    if args.desvirtualizar or args.perfil_cutgrass or args.retirar_antitamper:
        try:
            from prometheus_static import devirtualize, Unsupported
        except ImportError as exc:
            report["static_vm"] = {"status": "dependency_missing", "message": str(exc),
                                   "install": "python3 -m pip install -r requirements-static.txt"}
            vm_failed = True
        else:
            try:
                native_source, native_report = devirtualize(src, clean_sample=args.perfil_cutgrass, remove_antitamper=args.retirar_antitamper)
            except Unsupported as exc:
                report["static_vm"] = {"status": "unsupported", "message": str(exc)}
                vm_failed = True
            else:
                (salida / "vm_removed.lua").write_text(native_source, encoding="ascii")
                (salida / "static_vm.json").write_text(json.dumps(native_report, indent=2) + "\n", encoding="utf-8")
                report["static_vm"] = {"status": "lifted", "output": "vm_removed.lua",
                                       "report": "static_vm.json", "dispatcher_removed": True,
                                       "native_functions": native_report["native_functions"],
                                       "decoded_strings": len(native_report["decoded_strings"]),
                                       "antitamper_removed": native_report["antitamper_removed"],
                                       "antitamper_bypassed": native_report.get("antitamper_bypassed", False),
                                       "semantic_equivalence_verified": False,
                                       "containers_lifted": native_report.get("containers_lifted", 1),
                                       "lua_syntax": native_report["lua_syntax"]}
                report["limitations"][0] = "Vmify transformado en vm_removed.lua; equivalencia completa sin verificar."
                print(f"[+] Dispatcher eliminado: {native_report['native_functions']} funciones, "
                      f"{len(native_report['decoded_strings'])} cadenas descifradas.")
        if vm_failed:
            print("[!] Desvirtualizacion estatica: " + report["static_vm"]["message"])
    lua, desc, results, best = None, "", [], None
    exit_code = 3 if lex_error or vm_failed else 0
    if not args.solo_estatico:
        # La confirmacion precede incluso a la prueba del ejecutable --lua.
        approved = args.yes
        if not approved:
            print("Se ejecutara la muestra en Lua instrumentado. Para codigo no confiable, usa aislamiento externo sin red.")
            try:
                approved = input("¿Continuar? [s/N] ").strip().lower() in ("s", "si", "sí", "y", "yes")
            except EOFError:
                approved = False
        if not approved:
            report["execution_status"], exit_code = "cancelled", 2
        else:
            lua, desc = find_lua(args.lua)
            if not lua:
                report["execution_status"], exit_code = "runtime_missing", 2
                print("[!] No se encontro Lua. Indica el interprete con --lua; se conserva el analisis estatico.")
            else:
                # Ejecuta exactamente los bytes analizados, aunque el original cambie despues.
                snapshot = salida / "input.lua"
                snapshot.write_bytes(src)
                results, best = ejecutar_multi(lua, snapshot, salida, args)
                report["execution_status"] = "finished"
                exit_code = 0 if not lex_error and not vm_failed and all(r.status == "ok" for r in results) else 3
    if results:
        payloads, dynamic = collect_artifacts(salida, results)
        report["payloads"] = payloads
        report["functions"] = {r.name: json.loads((salida / r.name / "functions.json").read_text(encoding="utf-8"))
                               for r in results}
    else:
        dynamic = []
    report.update({"runtime": {"path": lua, "version": desc}, "passes": [asdict(r) for r in results],
                   "selected_pass": best, "dynamic_strings": len(dynamic), "exit_code": exit_code})
    extra = [(salida / p["file"]).read_bytes() for p in report["payloads"]]
    report["urls"] = escribir_strings(salida, static, dynamic, extra)
    (salida / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for result in results:
        print(f"[{result.name}] {ESTADOS[result.status]} ({result.wall_seconds}s)")
        if result.message:
            print(f"    {result.message[:300]}")
    if lex_error:
        print(f"[!] Analisis estatico parcial: {lex_error}")
    print(f"[+] {salida}: {len(static)} literales, {len(dynamic)} cadenas observadas, {len(report['payloads'])} payloads unicos.")
    print("[+] report.json contiene estados, limites y procedencias; cobertura desconocida.")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] Interrumpido; pueden quedar artefactos parciales.", file=sys.stderr)
        sys.exit(130)
