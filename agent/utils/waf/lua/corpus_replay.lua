local cjson = require("cjson.safe")
local semantic = require("waf.semantic")

local input = (arg and arg[1]) or (ngx and ngx.var.corpus_path)
assert(input, "corpus path is required")
local file = assert(io.open(input, "r"))
local rows = assert(cjson.decode(file:read("*a")))
file:close()

local miss_limit = tonumber((ngx and ngx.var.miss_limit) or 0) or 0
local result = {total = #rows, detected = 0, bySourceType = {}, byDetectedType = {}, misses = {}}
for _, row in ipairs(rows) do
    local hit
    if row.payload and row.payload ~= "" then
        hit = semantic.inspect(row.payload, row.path)
    end
    if not hit and row.path and row.path ~= "" then
        hit = semantic.inspect(row.path, row.path)
    end
    local source_type = tostring(row.attackType or "unknown")
    local bucket = result.bySourceType[source_type]
    if not bucket then
        bucket = {total = 0, detected = 0}
        result.bySourceType[source_type] = bucket
    end
    bucket.total = bucket.total + 1
    if hit then
        result.detected = result.detected + 1
        bucket.detected = bucket.detected + 1
        result.byDetectedType[hit.type] = (result.byDetectedType[hit.type] or 0) + 1
    elseif #result.misses < miss_limit then
        result.misses[#result.misses + 1] = row
    end
end
if miss_limit == 0 then result.misses = nil end
result.rate = result.total > 0 and result.detected / result.total or 0
local output = assert(cjson.encode(result))
if ngx then ngx.say(output) else io.write(output, "\n") end
