-- Per-request entry kept deliberately tiny. The complete engine is loaded once
-- per worker by require() and then reused/JIT-compiled for subsequent requests.
--
-- The module directory is registered here instead of through a nginx
-- `lua_package_path` directive. The bundled OpenResty image already declares
-- that directive in 1pwaf/data/conf/waf.conf, and a second declaration in the
-- same http block makes `nginx -t` fail with "lua_package_path directive is
-- duplicate", which aborted WAF enablement on a stock install. Resolving the
-- path from this file's own location also makes it independent of include order.
--
-- Modules are required as "waf.<name>" and sit next to this file, so `?` must map
-- to the PARENT of this directory: entry.lua is /www/waf/entry.lua, hence `?` is
-- /www/ and "waf.access" resolves to /www/waf/access.lua — the same mapping the
-- previous nginx-level directive provided.
local entry_source = debug.getinfo(1, "S").source:sub(2)
local module_dir = entry_source:match("^(.*[/\\])") or "./"
local module_root = module_dir:gsub("[/\\][^/\\]+[/\\]$", "/")
package.path = module_root .. "?.lua;" .. module_root .. "?/init.lua;" .. package.path

require("waf.access").run()