# Synthetic Prometheus fixtures

Based on Prometheus by Elias Oelschner, https://github.com/prometheus-lua/Prometheus

`source.lua` was written for this test suite. The other files are generated
outputs of the official Vmify, Weak, Medium and Strong presets, each at seeds
3, 17 and 42. The pinned upstream revision and hashes are in `manifest.json`.
Generated output is covered by section 4 of the upstream license.
No fixture calls HTTP APIs or requires Roblox. Tests compare stdout and returned
values on LuaJIT 2.1 (the Lua 5.1 target); they do not certify that Strong's inner VM is fully removed.
