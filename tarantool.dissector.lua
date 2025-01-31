
local msgpack = require 'MessagePack'
local json = require 'json'

-- constants
-- common
local GREETING_SIZE          = 128
local GREETING_SALT_OFFSET   = 64
local GREETING_SALT_SIZE     = 44

-- packet codes
local OK         = 0x00
local SELECT     = 0x01
local INSERT     = 0x02
local REPLACE    = 0x03
local UPDATE     = 0x04
local DELETE     = 0x05
local CALL_16    = 0x06
local AUTH       = 0x07
local EVAL       = 0x08
local UPSERT     = 0x09
local CALL       = 0x0a
local EXECUTE    = 0x0b
local NOP        = 0x0c
local PREPARE    = 0x0d
local CONFIRM    = 0x28
local ROLLBACK   = 0x29
local PING       = 0x40
local JOIN       = 0x41
local SUBSCRIBE  = 0x42
local VOTE_DEPRECATED = 0x43
local VOTE            = 0x44
local FETCH_SNAPSHOT  = 0x45
local REGISTER        = 0x46
local ID      = 0x49
local WATCH      = 0x4a
local EVENT      = 0x4c

-- packet keys
local REQUEST_TYPE  = 0x00
local TYPE          = 0x00
local SYNC          = 0x01
local REPLICA_ID    = 0x02
local LSN           = 0x03
local TIMESTAMP     = 0x04
local SCHEMA_VERSION = 0x05
local FLAGS         = 0x09
local SPACE_ID      = 0x10
local INDEX_ID      = 0x11
local LIMIT         = 0x12
local OFFSET        = 0x13
local ITERATOR      = 0x14
local INDEX_BASE    = 0x15
local KEY           = 0x20
local TUPLE         = 0x21
local FUNCTION_NAME = 0x22
local USER_NAME     = 0x23
local INSTANCE_UUID = 0x24
local CLUSTER_UUID  = 0x25
local VCLOCK        = 0x26
local EXPRESSION    = 0x27
local OPS           = 0x28
local BALLOT        = 0x29
local DATA          = 0x30
local ERROR         = 0x31

local BALLOT_IS_RO_CFG = 0x01
local BALLOT_VCLOCK  = 0x02
local BALLOT_GC_VCLOCK = 0x03
local BALLOT_IS_RO  = 0x04
local BALLOT_IS_ANON = 0x05
local BALLOT_IS_BOOTED = 0x06
local TUPLE_META    = 0x2a
local OPTIONS       = 0x2b
local ERROR_24      = 0x31
local METADATA      = 0x32
local BIND_METADATA = 0x33
local BIND_COUNT    = 0x34
local SQL_TEXT      = 0x40
local SQL_BIND      = 0x41
local SQL_INFO      = 0x42
local STMT_ID       = 0x43
local ERROR_VALUE   = 0x52
local FIELD_NAME    = 0x00
local FIELD_TYPE    = 0x01
local FIELD_COLL    = 0x02
local FIELD_IS_NULLABLE = 0x03
local FIELD_IS_AUTOINCREMENT = 0x04
local FIELD_SPAN    = 0x05
local IPROTO_VERSION=0x54
local IPROTO_FEATURES=0x55
local IPROTO_EVENT_KEY    = 0x57
local IPROTO_EVENT_DATA    = 0x58

-- declare the protocol
tarantool_proto = Proto("tarantool","Tarantool")
local f = tarantool_proto.fields
f.code = ProtoField.uint32('tnt.code', 'Code', base.DEC, {
    [SELECT]  = 'select',
    [INSERT]  = 'insert',
    [REPLACE] = 'replace',
    [UPDATE]  = 'update',
    [DELETE]  = 'delete',
    [CALL]    = 'call',
    [CALL_16] = 'call_16',
    [AUTH]    = 'auth',
    [EVAL]    = 'eval',
    [UPSERT]  = 'upsert',
    [EXECUTE] = 'execute',
    [NOP]     = 'nop',
    [PREPARE] = 'prepare',
    [CONFIRM] = 'confirm',
    [ROLLBACK] = 'rollback',
    [JOIN]    = 'join',
    [VOTE]    = 'vote',
    [VOTE_DEPRECATED] = 'vote_deprecated',
    [SUBSCRIBE] = 'subscribe',
    [FETCH_SNAPSHOT] = 'fetch_snapshot',
    [REGISTER] = 'register',
    [PING] = 'ping',
    [OK]   = 'OK',
    [ID]   = 'id',
    [WATCH]   = 'watch',
    [EVENT]   = 'event',
    [0x8000] = 'ERROR',
})
f.sync = ProtoField.uint32('tnt.sync', 'Sync', base.HEX)

f.transtype = ProtoField.string("tnt.transtype", "Type")
f.reply_time = ProtoField.relative_time("tnt.reply_time", "Reply time")

f.peer_new_in = ProtoField.framenum("tnt.reply_in", "New in", base.NONE)
f.peer_reply_in = ProtoField.framenum("tnt.reply_in", "Reply in", base.NONE)
f.copy_new_in = ProtoField.framenum("tnt.copy_reply_in", "Copy of new in", base.NONE)
f.copy_reply_in = ProtoField.framenum("tnt.copy_reply_in", "Copy of reply in", base.NONE)

f['function'] = ProtoField.string("tnt.function", "Function")
f.expression = ProtoField.string("tnt.expression", "Expression")
f.query = ProtoField.string("tnt.query", "Query")
f.space = ProtoField.string("tnt.space", "Space")
f.index = ProtoField.string("tnt.index", "index")
f.ops = ProtoField.string("tnt.ops", "OPS")
f.eventKey = ProtoField.string("tnt.event_key", "Event key")
f.eventData = ProtoField.string("tnt.event_data", "Event data")
f.extra = ProtoField.string("tnt.extra", "Extra")
f.version = ProtoField.string("tnt.version", "Version")
f.features = ProtoField.string("tnt.features", "Features")

local tcpStreamField = Field.new('tcp.stream')

local jsonDissector = Dissector.get("json")

local function add(v, pinfo, tree)
    if type(v) == 'array' then
        v = {array=v} -- json dissector seems to assume '{' and if not falls back to Line-based text data (1 lines)
    end
    local jsonString = json.encode(v)
    local jsonBytes = ByteArray.new(jsonString, true)
    local tvb = jsonBytes:tvb('JSON')
    jsonDissector:call(tvb, pinfo, tree)
end

local function map(tbl, callback)
    local result = {}
    for k,v in pairs(tbl) do
        result[k] = callback(v)
    end
    return result
end

local function table_kv_concat(tbl, sep)
    local result = {}
    local used_keys = {}
    for i, v in ipairs(tbl) do
        used_keys[i] = true
        table.insert(result, v)
    end
    for k, v in pairs(tbl) do
        if not used_keys[k] then
            table.insert(result, k .. ' = ' .. v)
        end
    end
    return table.concat(result, sep)
end

local function escape_call_arg(a)
    if type(a) == 'number' then
        return a
    elseif type(a) == 'string' then
        return '"' .. a .. '"'
    elseif type(a) == 'table' then
        return '{' .. table_kv_concat(map(a, escape_call_arg), ', ') .. '}'
    else
        return a
    end
end

local function parse_call(tbl, buffer, subtree, pinfo, tree)
    subtree:add(f['function'], tbl[FUNCTION_NAME])
    add(tbl[TUPLE], pinfo, tree)
end

local function parse_eval(tbl, buffer, subtree, pinfo, tree)
    subtree:add(f.expression, tbl[EXPRESSION])
    add(tbl[TUPLE], pinfo, tree)
end

local function parse_select(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID] -- int
    local index_id = tbl[INDEX_ID] -- int
    local limit    = tbl[LIMIT]    -- int
    local offset   = tbl[OFFSET]   -- int
    local iterator = tbl[ITERATOR] -- int
    local key      = tbl[KEY]      -- array

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    subtree:add(f.query, string.format(
            'SELECT FROM space %d WHERE index(%s) = (%s) LIMIT %s OFFSET %s ITERATOR %s',
            tostring(space_id),
            tostring(index_id),
            tostring(key_string),
            tostring(limit),
            tostring(offset),
            tostring(iterator)
    ))
end

local function parse_insert(tbl, buffer, subtree, pinfo, tree)
    subtree:add(f.space, tbl[SPACE_ID])
    add(tbl[TUPLE], pinfo, tree)
end

local function parse_delete(tbl, buffer, subtree)
    local key      = tbl[KEY]
    local space_id = tbl[SPACE_ID]
    local index_id = tbl[INDEX_ID]

    local key_string = table.concat(map(key, escape_call_arg), ', ')

    local descr = string.format(
        'DELETE FROM space(%d) WHERE index(%d) = (%s)',
        space_id,
        index_id,
        key_string
    )
    subtree:add(buffer, descr)
end

local function parse_upsert(tbl, buffer, subtree, pinfo, tree)
    subtree:add(f.space, tbl[SPACE_ID])
    subtree:add(f.index, tbl[INDEX_BASE])
    subtree:add(f.ops, tbl[OPS])
    add(tbl[TUPLE], pinfo, tree)
end

local function parse_auth(tbl, buffer, subtree)
    local user_name = tbl[USER_NAME]     -- str
    local tuple = tbl[TUPLE]             -- array

    -- chap-sha1 is the only supported mechanism (v. 2.10).
    local proto = tuple[1]
    local scramble = tuple[2]

    local descr = string.format(
       'Authentication with username "%s", protocol %s and scramble "%s"',
       user_name,
       proto,
       scramble
    )
    subtree:add(buffer, descr)
end

local function parse_update(tbl, buffer, subtree)
    local space_id = tbl[SPACE_ID]     -- int
    local index_id = tbl[INDEX_ID]     -- int
    local key = tbl[KEY]               -- array
    local tuple = tbl[TUPLE]           -- array

    subtree:add(buffer, 'space_id: ' .. space_id)
    local tuple_tree = subtree:add(buffer, 'tuple')
    local tuple_str = table.concat(map(tuple, escape_call_arg), ', ')

    tuple_tree:add(buffer, tuple_str)
    local key_string = table.concat(map(key, escape_call_arg), ', ')
    subtree:add(buffer, 'key: ' .. key_string)
end

local function parse_execute(tbl, buffer, subtree)
    local stmt_id = tbl[STMT_ID]     -- int
    local sql_text = tbl[SQL_TEXT]   -- str
    local sql_bind = tbl[SQL_BIND]   -- array

    local sql_bind_str = table.concat(map(sql_bind, escape_call_arg), ', ')
    if sql_bind_str ~= '' then
        sql_bind_str = string.format(', with parameter values "%s"', sql_bind_str)
    end

    if stmt_id ~= nil then
        local descr = string.format(
           'executing a prepared statement with id %d%s',
           stmt_id,
           sql_bind_str
        )
        subtree:add(buffer, descr)
    else
        local descr = string.format(
           'executing an SQL string "%s"%s',
           sql_text,
           sql_bind_str
        )
        subtree:add(buffer, descr)
    end
end

local function parse_prepare(tbl, buffer, subtree)
    local stmt_id = tbl[STMT_ID]     -- int
    local sql_text = tbl[SQL_TEXT]   -- str

    if stmt_id ~= nil then
        local descr = string.format(
           'prepare a statement with id %d',
           stmt_id
        )
        subtree:add(buffer, descr)
    else
        local descr = string.format(
           'preparing an SQL string "%s"',
           sql_text
        )
        subtree:add(buffer, descr)
    end
end

local function parse_confirm(tbl, buffer, subtree)
    local replica_id = tbl[REPLICA_ID]     -- int
    local lsn = tbl[LSN]                   -- int

    local descr = string.format(
       [[transactions originated from the instance with id = "%d"
        have achieved quorum and can be committed, up to and including lsn "%d".]],
       replica_id,
       lsn
    )
    subtree:add(buffer, descr)
end

local function parse_rollback(tbl, buffer, subtree)
    local replica_id = tbl[REPLICA_ID]     -- int
    local lsn = tbl[LSN]                   -- int

    local descr = string.format(
       [[transactions originated from the instance with id = "%d"
       couldn't achieve quorum for some reason and should be rolled back,
       down to lsn = "%d" and including it.]],
       replica_id,
       lsn
    )
    subtree:add(buffer, descr)
end

local function parse_subscribe(tbl, buffer, subtree)
    local vclock = tbl[VCLOCK]

    local srv_id = vclock[1]
    local srv_lsn = vclock[2]

    local descr = string.format(
       'Subscribe to server with id "%d" and lsn "%d"',
       srv_id,
       srv_lsn
    )
    subtree:add(buffer, descr)
end

local function parse_join(tbl, buffer, subtree)
    local uuid = tbl[INSTANCE_UUID]

    local descr = string.format(
       'Initial join request with uuid = "%s"',
       uuid
    )
    subtree:add(buffer, descr)
end

local function parse_error_response(tbl, buffer, subtree)
    local data = tbl[ERROR]
    if not data then
        subtree:add(buffer, '(empty response body)')
    else
        subtree:add(buffer, data)
    end
end

function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

local function parse_id(tbl, buffer, subtree)
    subtree:add(f.version, tbl[IPROTO_VERSION] or '(empty)')
    subtree:add(f.features, dump(tbl[IPROTO_FEATURES]) or '(empty)')
end

local function parse_watch(tbl, buffer, subtree)
    subtree:add(f.eventKey, tbl[IPROTO_EVENT_KEY] or '(empty)')
end

local function parse_event(tbl, buffer, subtree)
    subtree:add_expert_info(PI_SEQUENCE, PI_ERROR, "Event")
    subtree:add(f.eventKey, tbl[IPROTO_EVENT_KEY] or '(empty)')
    subtree:add(f.eventData, tbl[IPROTO_EVENT_DATA] or '(empty)')
end

local function parse_response(tbl, buffer, subtree, pinfo, tree)
    add(tbl[DATA], pinfo, tree)
end

local function parse_nop(tbl, buffer, subtree)
    subtree:add(buffer, 'NOP (No Operation')
end

local function parser_not_implemented(tbl, buffer, subtree)
    subtree:add(buffer, 'parser not yet implemented (or unknown packet?)')
end

local function code_to_command(code)

    local codes = {
        [SELECT]  = {name = 'select', decoder = parse_select},
        [INSERT]  = {name = 'insert', decoder = parse_insert},
        [REPLACE] = {name = 'replace', decoder = parse_insert},
        [UPDATE]  = {name = 'update', decoder = parse_update},
        [DELETE]  = {name = 'delete', decoder = parse_delete},
        [CALL]    = {name = 'call', decoder = parse_call},
        [CALL_16] = {name = 'call_16', decoder = parser_not_implemented}, -- Deprecated.
        [AUTH]    = {name = 'auth', is_response = true, decoder = parse_auth},
        [EVAL]    = {name = 'eval', decoder = parse_eval},
        [UPSERT]  = {name = 'upsert', decoder = parse_upsert},
        [EXECUTE] = {name = 'execute', decoder = parse_execute},
        [NOP]     = {name = 'nop', decoder = parse_nop},
        [PREPARE] = {name = 'prepare', decoder = parse_prepare},
        [CONFIRM] = {name = 'confirm', decoder = parse_confirm},
        [ROLLBACK] = {name = 'rollback', decoder = parse_rollback},
        [JOIN]    = {name = 'join', decoder = parse_join},
        [VOTE]    = {name = 'vote', decoder = parser_not_implemented},
        [VOTE_DEPRECATED] = {name = 'vote_deprecated', decoder = parser_not_implemented},
        [SUBSCRIBE] = {name = 'subscribe', decoder = parse_subscribe},
        [FETCH_SNAPSHOT] = {name = 'fetch_snapshot', decoder = parser_not_implemented},
        [REGISTER] = {name = 'register', decoder = parser_not_implemented},
        [ID] = {name = 'id', decoder = parse_id },
        [WATCH] = {name = 'watch', decoder = parse_watch },
        [EVENT] = {name = 'event', decoder = parse_event },

        -- Admin command codes
        [PING] = {name = 'ping', decoder = parser_not_implemented},

        -- Value for <code> key in response can be:
        [OK]   = {name = 'OK', is_response = true, decoder = parse_response},
        --[0x8XXX] = {name = 'ERROR', is_response = true},
    };
    if code >= 0x8000 then
        return {name = 'ERROR', is_response = true, decoder = parse_error_response}
    end

    local unknown_code = {name = 'UNKNOWN', decoder = parser_not_implemented}

    return (codes[code] or unknown_code)
end

-- cross-refs

--transnum -> {new=framenums, reply=framenums, new_time=time, reply_time=time}
transnums ={}

function getTransInfo(transnumb)
    local transinfo = transnums[transnumb]
    if transinfo == nil then
        transinfo = {new={}, reply={}, new_time=nil, reply_time=nil}
        transnums[transnumb] = transinfo
    end
    return transinfo
end

function seenNew(framenum, transnumb, time)
    local transinfo = getTransInfo(transnumb)
    transinfo.new[framenum] = 0
    if transinfo.new_time == nil then transinfo.new_time = time end
end

function seenReply(framenum, transnumb, time)
    local transinfo = getTransInfo(transnumb)
    transinfo.reply[framenum] = 0
    if transinfo.reply_time == nil then transinfo.reply_time = time end
end

function addTransInfo(subtree, transtype, my_framenum, transinfo)
    if (transinfo == nil or (next(transinfo.reply) == nil))
            and transtype ~= "reply"
    then
        subtree:add_expert_info(PI_SEQUENCE, PI_ERROR, "No reply")
    end

    if transinfo ~= nil then
        for peer_framenum in pairs(transinfo.new) do
            if my_framenum ~= peer_framenum then subtree:add(transtype=="new" and f.copy_new_in or f.peer_new_in, peer_framenum):set_generated() end
        end
        for peer_framenum in pairs(transinfo.reply) do
            if my_framenum ~= peer_framenum then subtree:add(transtype=="reply" and f.copy_reply_in or f.peer_reply_in, peer_framenum):set_generated() end
        end

        if transinfo.new_time and transinfo.reply_time then
            local s,nsfrac = math.modf(transinfo.reply_time - transinfo.new_time)
            print(transinfo.reply_time, transinfo.new_time)
            local dnstime = NSTime(s, math.floor(nsfrac*1e9+0.5))
            subtree:add(f.reply_time, dnstime):set_generated()
        end
    end
end

-- create a function to dissect it
function tarantool_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "Tarantool"

    if buffer(0, 9):string() == "Tarantool" then
        local transnum = tcpStreamField().value*0x100000000 + 0
        if not pinfo.visited then
            seenNew(pinfo.number, transnum, pinfo.abs_ts)
        end

        pinfo.cols.info = 'Greeting packet. ' .. tostring(pinfo.cols.info)

        local subtree = tree:add(tarantool_proto, buffer(),"Tarantool greeting packet")
        subtree:add(f.transtype, 'new'):set_generated()
        addTransInfo(subtree, 'new', pinfo.number, transnums[transnum])
        subtree:add(buffer(0, 64), "Server version: " .. buffer(0, 64):string())
        subtree:add(buffer(64, 44), "Salt: " .. buffer(64, 44):string())
        subtree:add(buffer(108), "Reserved space")
        return buffer(0, 9):len()
    end

    local iterator = msgpack.unpacker(buffer:raw())
    local _, packet_length = iterator()

    local size_length, header_data = iterator()
    size_length = size_length - 1
    local packet_buffer = buffer(size_length)
    local desegment_len = size_length + packet_length - buffer:len()
    if desegment_len > 0 then
        pinfo.desegment_len = desegment_len
        pinfo.desegment_offset = 0
        return DESEGMENT_ONE_MORE_SEGMENT
    end

    local subtree = tree:add(tarantool_proto, buffer(),"Tarantool protocol data")
    subtree:add(f.code, header_data[TYPE])
    local sync = header_data[SYNC] or -1

    local header_length, body_data = iterator()
    header_length = header_length - 1
    local body_buffer = buffer(header_length)

    local command = code_to_command(header_data[TYPE])

    if sync >= 0 then
        subtree:add(f.sync, sync)
        local transnum = tcpStreamField().value*0x100000000 + sync
        if not pinfo.visited then
            --subtree:add(buffer(), 'transnum='..transnum)
            if command.is_response then
                seenReply(pinfo.number, transnum, pinfo.abs_ts)
            else -- new
                seenNew(pinfo.number, transnum, pinfo.abs_ts)
            end
        end
        local transtype = command.is_response and "reply" or "new"
        subtree:add(f.transtype, transtype):set_generated()
        addTransInfo(subtree, transtype, pinfo.number, transnums[transnum])
    end

    if not command.is_response then
        local decoder = command.decoder or parser_not_implemented
        decoder(body_data, body_buffer, subtree, pinfo, tree)

        pinfo.cols.info = command.name:gsub("^%l", string.upper) .. ' request. ' .. tostring(pinfo.cols.info)
        --[[print(body_data, bytes_used)
        for k,v in pairs(body_data) do
            print(k,v)
        end]]
        -- subtree:add( buffer(0,4),"Request Type: " .. buffer(0,4):le_uint() .. ' ' .. requestName(buffer(0,4):le_uint()) )
        --        request(buffer, subtree)
    else
        command.decoder(body_data, body_buffer, subtree, pinfo, tree)
        pinfo.cols.info = 'Response. ' .. tostring(pinfo.cols.info)
    end

    local i = 0
    while i < 10 do
        local extra_offset, extra_body = iterator()
        if extra_offset ~= nil then
            if type(extra_body)=='table' then
                local data = extra_body[DATA]
                if data == nil then
                    subtree:add(f.extra, dump(extra_body))
                else
                    add(data, pinfo, tree)
                end
            else
                subtree:add(f.extra, dump(extra_body))
            end
        end
        i = i + 1
    end

    return request_length

end

tarantool_proto.prefs.ports = Pref.string("Port(s)", "3301-3302,4308", "Specify port numbers (comma-separated) or port ranges (dash-separated) or mix")

local function add_ports()
    local tcp_table = DissectorTable.get("tcp.port")
    tcp_table:add(tarantool_proto.prefs.ports,tarantool_proto)
end

function tarantool_proto.prefs_changed()
    add_ports()
    reload()
end

add_ports()
