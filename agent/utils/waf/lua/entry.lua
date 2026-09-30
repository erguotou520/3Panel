-- Per-request entry kept deliberately tiny. The complete engine is loaded once
-- per worker by require() and then reused/JIT-compiled for subsequent requests.
require("waf.access").run()
