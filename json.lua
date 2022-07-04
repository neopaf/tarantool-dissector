---
-- Library methods for handling JSON data. It handles JSON encoding and
-- decoding according to RFC 4627.
--
-- There is a straightforward mapping between JSON and Lua data types. One
-- exception is JSON <code>NULL</code>, which is not the same as Lua
-- <code>nil</code>. (A better match for Lua <code>nil</code> is JavaScript
-- <code>undefined</code>.) <code>NULL</code> values in JSON are represented by
-- the special value <code>json.NULL</code>.
--
-- @author Martin Holst Swende
-- @author David Fifield
-- @author Patrick Donnelly
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- Version 0.4
-- Created 01/25/2010 - v0.1 - created by Martin Holst Swende <martin@swende.se>
-- Heavily modified 02/22/2010 - v0.3. Rewrote the parser into an OO-form, to not have to handle
-- all kinds of state with parameters and return values.
-- Modified 02/27/2010 - v0.4 Added unicode handling (written by David Fifield). Renamed toJson
-- and fromJson into generate() and parse(), implemented more proper numeric parsing and added some more error checking.

local json = {}

-- See section 2.5 for escapes.
-- For convenience, ESCAPE_TABLE maps to escape sequences complete with
-- backslash, and REVERSE_ESCAPE_TABLE maps from single escape characters
-- (no backslash).
local ESCAPE_TABLE = {}
--do
	local escapes = {
		["\x22"] = "\"",
		["\x5C"] = "\\",
		["\x2F"] = "/",
		["\x08"] = "b",
		["\x0C"] = "f",
		["\x0A"] = "n",
		["\x0D"] = "r",
		["\x09"] = "t",
	}
	for k, v in pairs(escapes) do
		ESCAPE_TABLE[k] = "\\" .. v
	end
--end

---Escapes a string
---@param str string
---@return string where the special chars have been escaped
local function escape(str)
	return "\"" .. string.gsub(str, ".", ESCAPE_TABLE) .. "\""
end

--- Checks what JSON type a variable will be treated as when generating JSON
---@param var any a variable to inspect
---@return string containing the JSON type. Valid values are "array", "object", "number", "string", "boolean", and "null"
local function typeof(var)
	local t = type(var)
	if var == NULL then
		return "null"
	elseif t == "table" then
		local mtval = rawget(getmetatable(var) or {}, "json")
		if mtval == "array" or (mtval ~= "object" and #var > 0) then
			return "array"
		else
			return "object"
		end
	else
		return t
	end
	error("Unknown data type in typeof")
end

---Creates json data from an object
---@param obj table containing data
---@return string containing valid json
function json.encode(obj)
	-- NULL-check must be performed before
	-- checking type == table, since the NULL-object
	-- is a table
	if obj == NULL then
		return "null"
	elseif obj == false then
		return "false"
	elseif obj == true then
		return "true"
	elseif type(obj) == "number" then
		return tostring(obj)
	elseif type(obj) == "string" then
		return escape(obj)
	elseif type(obj) == "table" then
		local elems, jtype
		elems = {}
		jtype = typeof(obj)
		if jtype == "array" then
			for _, v in ipairs(obj) do
				elems[#elems + 1] = json.encode(v)
			end
			return "[" .. table.concat(elems, ", ") .. "]"
		elseif jtype == "object" then
			for k, v in pairs(obj) do
				elems[#elems + 1] = escape(k) .. ": " .. json.encode(v)
			end
			return "{" .. table.concat(elems, ", ") .. "}"
		end
	end
	error("Unknown data type in generate")
end

--print(generate({paf='molodets'}))

return json
