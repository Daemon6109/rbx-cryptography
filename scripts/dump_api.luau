--!strict
-- Dumps the public Cryptography API as dotted paths.
-- Run via Studio/roblox-cli from repo root; prints sorted lines.

local function isCallable(v: any): boolean
	local t = typeof(v)
	if t == "function" then
		return true
	end
	if t == "table" then
		local mt = getmetatable(v)
		return mt ~= nil and mt.__call ~= nil
	end
	return false
end

local function walk(prefix: string, value: any, out: { string }, seen: { [any]: boolean })
	local t = typeof(value)
	if t ~= "table" then
		table.insert(out, prefix .. (isCallable(value) and "()" or ""))
		return
	end

	if seen[value] then
		table.insert(out, prefix .. " (cycle)")
		return
	end
	seen[value] = true

	local keys = {}
	for k in pairs(value) do
		if typeof(k) == "string" then
			table.insert(keys, k)
		end
	end
	table.sort(keys)

	if #keys == 0 then
		table.insert(out, prefix)
		return
	end

	for _, k in ipairs(keys) do
		walk(prefix .. "." .. k, value[k], out, seen)
	end
end

-- Adjust require path if running from elsewhere
local Cryptography = require("../src")

local paths = {}
walk("Cryptography", Cryptography, paths, {})
table.sort(paths)
for _, p in ipairs(paths) do
	print(p)
end
