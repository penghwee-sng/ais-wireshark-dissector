-- AIS Dissector for Wireshark
-- Install this script by placing it in your Wireshark plugins directory:
-- Windows: %APPDATA%\Wireshark\plugins\
-- Linux/macOS: ~/.local/lib/wireshark/plugins/

-- Create the AIS protocol
local ais_proto = Proto("ais", "Automatic Identification System")

-- Define protocol fields that will appear in the Wireshark UI
local fields = {
    -- NMEA header fields
    format = ProtoField.string("ais.format", "Format"),
    num_fragments = ProtoField.uint8("ais.num_fragments", "Number of Fragments"),
    fragment_num = ProtoField.uint8("ais.fragment_num", "Fragment Number"),
    msg_id = ProtoField.string("ais.msg_id", "Message ID"),
    channel = ProtoField.string("ais.channel", "Channel"),
    payload = ProtoField.string("ais.payload", "Payload"),
    fill_bits = ProtoField.uint8("ais.fill_bits", "Fill Bits"),
    checksum = ProtoField.string("ais.checksum", "Checksum"),
    
    -- AIS message common fields
    msg_type = ProtoField.uint8("ais.msg_type", "Message Type", base.DEC, nil, 0x3F),
    msg_type_desc = ProtoField.string("ais.msg_type_desc", "Message Type Description"),
    repeat_indicator = ProtoField.uint8("ais.repeat_indicator", "Repeat Indicator"),
    mmsi = ProtoField.uint32("ais.mmsi", "MMSI"),
    
    -- Position report fields (Types 1, 2, 3, 18, 19)
    nav_status = ProtoField.uint8("ais.nav_status", "Navigation Status"),
    nav_status_text = ProtoField.string("ais.nav_status_text", "Navigation Status Text"),
    rot = ProtoField.int8("ais.rot", "Rate of Turn"),
    rot_text = ProtoField.string("ais.rot_text", "Rate of Turn Text"),
    sog = ProtoField.float("ais.sog", "Speed Over Ground (knots)"),
    pos_accuracy = ProtoField.uint8("ais.pos_accuracy", "Position Accuracy"),
    longitude = ProtoField.float("ais.longitude", "Longitude"),
    latitude = ProtoField.float("ais.latitude", "Latitude"),
    cog = ProtoField.float("ais.cog", "Course Over Ground"),
    true_heading = ProtoField.uint16("ais.true_heading", "True Heading"),
    timestamp = ProtoField.uint8("ais.timestamp", "Timestamp"),
    
    -- Static and voyage data fields (Type 5)
    ais_version = ProtoField.uint8("ais.ais_version", "AIS Version"),
    imo = ProtoField.uint32("ais.imo", "IMO Number"),
    callsign = ProtoField.string("ais.callsign", "Callsign"),
    shipname = ProtoField.string("ais.shipname", "Vessel Name"),
    ship_type = ProtoField.uint8("ais.ship_type", "Ship Type"),
    ship_type_text = ProtoField.string("ais.ship_type_text", "Ship Type Text"),
    dim_to_bow = ProtoField.uint16("ais.dim_to_bow", "Dimension to Bow"),
    dim_to_stern = ProtoField.uint16("ais.dim_to_stern", "Dimension to Stern"),
    dim_to_port = ProtoField.uint8("ais.dim_to_port", "Dimension to Port"),
    dim_to_starboard = ProtoField.uint8("ais.dim_to_starboard", "Dimension to Starboard"),
    vessel_length = ProtoField.uint16("ais.vessel_length", "Vessel Length"),
    vessel_width = ProtoField.uint16("ais.vessel_width", "Vessel Width"),
    fix_type = ProtoField.uint8("ais.fix_type", "Fix Type"),
    eta_month = ProtoField.uint8("ais.eta_month", "ETA Month"),
    eta_day = ProtoField.uint8("ais.eta_day", "ETA Day"),
    eta_hour = ProtoField.uint8("ais.eta_hour", "ETA Hour"),
    eta_minute = ProtoField.uint8("ais.eta_minute", "ETA Minute"),
    draught = ProtoField.float("ais.draught", "Draught (meters)"),
    destination = ProtoField.string("ais.destination", "Destination"),
    
    -- Part number for message type 24
    part_number = ProtoField.uint8("ais.part_number", "Part Number"),
    vendor_id = ProtoField.string("ais.vendor_id", "Vendor ID"),
}

-- Register the fields with the protocol
ais_proto.fields = fields

-- Expert info fields for warnings and errors
local ais_checksum_error = ProtoExpert.new("ais.checksum.error", "AIS Checksum Error", expert.group.CHECKSUM, expert.severity.ERROR)
local ais_multipart_incomplete = ProtoExpert.new("ais.multipart.incomplete", "Incomplete Multipart Message", expert.group.PROTOCOL, expert.severity.NOTE)
local ais_invalid_format = ProtoExpert.new("ais.format.invalid", "Invalid AIS Format", expert.group.MALFORMED, expert.severity.ERROR)

ais_proto.experts = {
    ais_checksum_error,
    ais_multipart_incomplete,
    ais_invalid_format
}

-- Create a table to store multipart messages between dissection calls
local multipart_cache = {}

-- Utility functions for bit operations
local function getBits(data, start, length)
    local result = 0
    for i = 0, length - 1 do
        local byteIndex = math.floor((start + i) / 6) + 1
        if byteIndex > #data then break end
        
        local char = string.sub(data, byteIndex, byteIndex)
        local charValue = string.byte(char) - 48
        if charValue > 40 then charValue = charValue - 8 end
        
        local bitIndex = (start + i) % 6
        -- Use bit32 instead of bit
        local bit = bit32.band(charValue, bit32.lshift(1, (5 - bitIndex))) ~= 0
        
        if bit then
            result = bit32.bor(result, bit32.lshift(1, (length - i - 1)))
        end
    end
    return result
end

local function getBitsAsString(data, start, length)
    local result = ""
    local byteCount = math.ceil(length / 6)
    
    for i = 0, byteCount - 1 do
        local bytePos = start + (i * 6)
        local charBits = getBits(data, bytePos, 6)
        if charBits > 0 then
            result = result .. string.char(charBits + 64)
        end
    end
    
    return result:gsub("@", ""):gsub("^%s*(.-)%s*$", "%1") -- Trim spaces and remove @ characters
end

local function signedInt(value, bits)
    local maxVal = 2^(bits-1)
    if value >= maxVal then
        return value - 2^bits
    end
    return value
end

-- AIS message types
local messageTypes = {
    [1] = "Position Report Class A",
    [2] = "Position Report Class A (Assigned schedule)",
    [3] = "Position Report Class A (Response to interrogation)",
    [4] = "Base Station Report",
    [5] = "Static and Voyage Related Data",
    [18] = "Standard Class B Position Report",
    [19] = "Extended Class B Position Report",
    [21] = "Aid-to-Navigation Report",
    [24] = "Static Data Report",
}

-- Navigation status descriptions
local navigationStatus = {
    [0] = "Under way using engine",
    [1] = "At anchor",
    [2] = "Not under command",
    [3] = "Restricted manoeuverability",
    [4] = "Constrained by her draught",
    [5] = "Moored",
    [6] = "Aground",
    [7] = "Engaged in Fishing",
    [8] = "Under way sailing",
    [9] = "Reserved for future amendment of Navigational Status for HSC",
    [10] = "Reserved for future amendment of Navigational Status for WIG",
    [11] = "Reserved for future use",
    [12] = "Reserved for future use",
    [13] = "Reserved for future use",
    [14] = "AIS-SART is active",
    [15] = "Not defined (default)",
}

-- Ship types
local shipTypes = {
    [0] = "Not available",
    [1] = "Reserved",
    [2] = "Reserved",
    [3] = "Reserved",
    [4] = "Reserved",
    [5] = "Reserved",
    [6] = "Reserved",
    [7] = "Reserved",
    [8] = "Reserved",
    [9] = "Reserved",
    [10] = "Reserved",
    [11] = "Reserved",
    [12] = "Reserved",
    [13] = "Reserved",
    [14] = "Reserved",
    [15] = "Reserved",
    [16] = "Reserved",
    [17] = "Reserved",
    [18] = "Reserved",
    [19] = "Reserved",
    [20] = "Wing in ground (WIG), all ships of this type",
    [21] = "Wing in ground (WIG), Hazardous category A",
    [22] = "Wing in ground (WIG), Hazardous category B",
    [23] = "Wing in ground (WIG), Hazardous category C",
    [24] = "Wing in ground (WIG), Hazardous category D",
    [25] = "Wing in ground (WIG), Reserved for future use",
    [26] = "Wing in ground (WIG), Reserved for future use",
    [27] = "Wing in ground (WIG), Reserved for future use",
    [28] = "Wing in ground (WIG), Reserved for future use",
    [29] = "Wing in ground (WIG), Reserved for future use",
    [30] = "Fishing",
    [31] = "Towing",
    [32] = "Towing: length exceeds 200m or breadth exceeds 25m",
    [33] = "Dredging or underwater ops",
    [34] = "Diving ops",
    [35] = "Military ops",
    [36] = "Sailing",
    [37] = "Pleasure Craft",
    [38] = "Reserved",
    [39] = "Reserved",
    [40] = "High speed craft (HSC), all ships of this type",
    [41] = "High speed craft (HSC), Hazardous category A",
    [42] = "High speed craft (HSC), Hazardous category B",
    [43] = "High speed craft (HSC), Hazardous category C",
    [44] = "High speed craft (HSC), Hazardous category D",
    [45] = "High speed craft (HSC), Reserved for future use",
    [46] = "High speed craft (HSC), Reserved for future use",
    [47] = "High speed craft (HSC), Reserved for future use",
    [48] = "High speed craft (HSC), Reserved for future use",
    [49] = "High speed craft (HSC), Reserved for future use",
    [50] = "Pilot Vessel",
    [51] = "Search and Rescue vessel",
    [52] = "Tug",
    [53] = "Port Tender",
    [54] = "Anti-pollution equipment",
    [55] = "Law Enforcement",
    [56] = "Spare - Local Vessel",
    [57] = "Spare - Local Vessel",
    [58] = "Medical Transport",
    [59] = "Noncombatant ship according to RR Resolution No. 18",
    [60] = "Passenger, all ships of this type",
    [61] = "Passenger, Hazardous category A",
    [62] = "Passenger, Hazardous category B",
    [63] = "Passenger, Hazardous category C",
    [64] = "Passenger, Hazardous category D",
    [65] = "Passenger, Reserved for future use",
    [66] = "Passenger, Reserved for future use",
    [67] = "Passenger, Reserved for future use",
    [68] = "Passenger, Reserved for future use",
    [69] = "Passenger, Reserved for future use",
    [70] = "Cargo, all ships of this type",
    [71] = "Cargo, Hazardous category A",
    [72] = "Cargo, Hazardous category B",
    [73] = "Cargo, Hazardous category C",
    [74] = "Cargo, Hazardous category D",
    [75] = "Cargo, Reserved for future use",
    [76] = "Cargo, Reserved for future use",
    [77] = "Cargo, Reserved for future use",
    [78] = "Cargo, Reserved for future use",
    [79] = "Cargo, Reserved for future use",
    [80] = "Tanker, all ships of this type",
    [81] = "Tanker, Hazardous category A",
    [82] = "Tanker, Hazardous category B",
    [83] = "Tanker, Hazardous category C",
    [84] = "Tanker, Hazardous category D",
    [85] = "Tanker, Reserved for future use",
    [86] = "Tanker, Reserved for future use",
    [87] = "Tanker, Reserved for future use",
    [88] = "Tanker, Reserved for future use",
    [89] = "Tanker, Reserved for future use",
    [90] = "Other Type, all ships of this type",
    [91] = "Other Type, Hazardous category A",
    [92] = "Other Type, Hazardous category B",
    [93] = "Other Type, Hazardous category C",
    [94] = "Other Type, Hazardous category D",
    [95] = "Other Type, Reserved for future use",
    [96] = "Other Type, Reserved for future use",
    [97] = "Other Type, Reserved for future use",
    [98] = "Other Type, Reserved for future use",
    [99] = "Other Type, no additional information",
}

-- Parse the NMEA sentence and process the AIS data
local function dissect_ais_payload(payload, tree)
    local messageType = getBits(payload, 0, 6)
    local repeatIndicator = getBits(payload, 6, 2)
    local mmsi = getBits(payload, 8, 30)
    
    tree:add(fields.msg_type, messageType)
    tree:add(fields.msg_type_desc, messageTypes[messageType] or "Unknown message type")
    tree:add(fields.repeat_indicator, repeatIndicator)
    tree:add(fields.mmsi, mmsi)
    
    if messageType == 1 or messageType == 2 or messageType == 3 then
        -- Position report Class A
        local navStatus = getBits(payload, 38, 4)
        local rot = getBits(payload, 42, 8)
        local sog = getBits(payload, 50, 10) / 10 -- Speed over ground in knots
        local posAccuracy = getBits(payload, 60, 1) -- Position accuracy
        
        local longitude = getBits(payload, 61, 28)
        local longVal = signedInt(longitude, 28) / 600000
        
        local latitude = getBits(payload, 89, 27)
        local latVal = signedInt(latitude, 27) / 600000
        
        local cog = getBits(payload, 116, 12) / 10 -- Course over ground
        local trueHeading = getBits(payload, 128, 9) -- True heading
        local timestamp = getBits(payload, 137, 6) -- UTC Timestamp
        
        tree:add(fields.nav_status, navStatus)
        tree:add(fields.nav_status_text, navigationStatus[navStatus] or "Unknown")
        
        tree:add(fields.rot, rot)
        if rot == 128 then
            tree:add(fields.rot_text, "Not available")
        else
            local rotVal = signedInt(rot, 8)
            if rotVal == 0 then
                tree:add(fields.rot_text, "0 deg/min")
            elseif rotVal == 127 then
                tree:add(fields.rot_text, "Turning right at more than 5 deg/30s")
            elseif rotVal == -127 then
                tree:add(fields.rot_text, "Turning left at more than 5 deg/30s")
            else
                tree:add(fields.rot_text, string.format("%.1f deg/min", (rotVal / 4.733) ^ 2 * (rotVal > 0 and 1 or -1)))
            end
        end
        
        tree:add(fields.sog, sog)
        tree:add(fields.pos_accuracy, posAccuracy)
        tree:add(fields.longitude, longVal)
        tree:add(fields.latitude, latVal)
        tree:add(fields.cog, cog)
        tree:add(fields.true_heading, trueHeading)
        tree:add(fields.timestamp, timestamp)
        
    elseif messageType == 5 then
        -- Static and voyage related data
        local aisVersion = getBits(payload, 38, 2)
        local imo = getBits(payload, 40, 30)
        local callsign = getBitsAsString(payload, 70, 42)
        local shipname = getBitsAsString(payload, 112, 120)
        local shipType = getBits(payload, 232, 8)
        
        -- Dimensions
        local toBow = getBits(payload, 240, 9)
        local toStern = getBits(payload, 249, 9)
        local toPort = getBits(payload, 258, 6)
        local toStarboard = getBits(payload, 264, 6)
        
        local fixType = getBits(payload, 270, 4)
        local etaMonth = getBits(payload, 274, 4)
        local etaDay = getBits(payload, 278, 5)
        local etaHour = getBits(payload, 283, 5)
        local etaMinute = getBits(payload, 288, 6)
        local draught = getBits(payload, 294, 8) / 10 -- in meters
        local destination = getBitsAsString(payload, 302, 120)
        
        tree:add(fields.ais_version, aisVersion)
        tree:add(fields.imo, imo)
        tree:add(fields.callsign, callsign)
        tree:add(fields.shipname, shipname)
        tree:add(fields.ship_type, shipType)
        tree:add(fields.ship_type_text, shipTypes[shipType] or "Unknown")
        
        tree:add(fields.dim_to_bow, toBow)
        tree:add(fields.dim_to_stern, toStern)
        tree:add(fields.dim_to_port, toPort)
        tree:add(fields.dim_to_starboard, toStarboard)
        tree:add(fields.vessel_length, toBow + toStern)
        tree:add(fields.vessel_width, toPort + toStarboard)
        
        tree:add(fields.fix_type, fixType)
        tree:add(fields.eta_month, etaMonth)
        tree:add(fields.eta_day, etaDay)
        tree:add(fields.eta_hour, etaHour)
        tree:add(fields.eta_minute, etaMinute)
        tree:add(fields.draught, draught)
        tree:add(fields.destination, destination)
        
    elseif messageType == 18 or messageType == 19 then
        -- Class B position report
        local sog = getBits(payload, 46, 10) / 10  -- Speed over ground in knots
        local posAccuracy = getBits(payload, 56, 1) -- Position accuracy
        
        local longitude = getBits(payload, 57, 28)
        local longVal = signedInt(longitude, 28) / 600000
        
        local latitude = getBits(payload, 85, 27)
        local latVal = signedInt(latitude, 27) / 600000
        
        local cog = getBits(payload, 112, 12) / 10  -- Course over ground
        local trueHeading = getBits(payload, 124, 9)  -- True heading
        local timestamp = getBits(payload, 133, 6)  -- UTC Timestamp
        
        tree:add(fields.sog, sog)
        tree:add(fields.pos_accuracy, posAccuracy)
        tree:add(fields.longitude, longVal)
        tree:add(fields.latitude, latVal)
        tree:add(fields.cog, cog)
        tree:add(fields.true_heading, trueHeading)
        tree:add(fields.timestamp, timestamp)
        
        if messageType == 19 then
            -- Additional data for message type 19
            local shipname = getBitsAsString(payload, 143, 120)
            local shipType = getBits(payload, 263, 8)
            
            -- Dimensions
            local toBow = getBits(payload, 271, 9)
            local toStern = getBits(payload, 280, 9)
            local toPort = getBits(payload, 289, 6)
            local toStarboard = getBits(payload, 295, 6)
            
            tree:add(fields.shipname, shipname)
            tree:add(fields.ship_type, shipType)
            tree:add(fields.ship_type_text, shipTypes[shipType] or "Unknown")
            
            tree:add(fields.dim_to_bow, toBow)
            tree:add(fields.dim_to_stern, toStern)
            tree:add(fields.dim_to_port, toPort)
            tree:add(fields.dim_to_starboard, toStarboard)
            tree:add(fields.vessel_length, toBow + toStern)
            tree:add(fields.vessel_width, toPort + toStarboard)
        end
    elseif messageType == 24 then
        -- Static data report
        local partNumber = getBits(payload, 38, 2)
        tree:add(fields.part_number, partNumber)
        
        if partNumber == 0 then
            local shipname = getBitsAsString(payload, 40, 120)
            tree:add(fields.shipname, shipname)
        elseif partNumber == 1 then
            local shipType = getBits(payload, 40, 8)
            local vendorId = getBitsAsString(payload, 48, 18)
            local callsign = getBitsAsString(payload, 90, 42)
            
            -- Dimensions
            local toBow = getBits(payload, 132, 9)
            local toStern = getBits(payload, 141, 9)
            local toPort = getBits(payload, 150, 6)
            local toStarboard = getBits(payload, 156, 6)
            
            tree:add(fields.ship_type, shipType)
            tree:add(fields.ship_type_text, shipTypes[shipType] or "Unknown")
            tree:add(fields.vendor_id, vendorId)
            tree:add(fields.callsign, callsign)
            
            tree:add(fields.dim_to_bow, toBow)
            tree:add(fields.dim_to_stern, toStern)
            tree:add(fields.dim_to_port, toPort)
            tree:add(fields.dim_to_starboard, toStarboard)
            tree:add(fields.vessel_length, toBow + toStern)
            tree:add(fields.vessel_width, toPort + toStarboard)
        end
    end
end

-- Parse NMEA sentence and extract AIS components
local function parse_nmea(nmeaString, pinfo, tree)
    print("Parsing NMEA: " .. nmeaString)
    -- Improved NMEA parsing that properly handles empty fields
    local parts = {}
    
    -- First, strip off any trailing whitespace and newlines
    nmeaString = nmeaString:gsub("%s+$", "")
    
    -- Extract all fields including empty ones
    for field in (nmeaString..","):gmatch("(.-),") do
        table.insert(parts, field)
    end
    
    if #parts < 7 then
        tree:add_proto_expert_info(ais_invalid_format, "Invalid NMEA message format (too few parts)")
        return false
    end
    
    -- Extract the checksum which might be in the last field
    local checksum
    if parts[#parts]:match("%*%x%x") then
        checksum = parts[#parts]:match("%*(%x%x)")
        parts[#parts] = parts[#parts]:gsub("%*%x%x", "")
    end
    
    -- Add NMEA components to the tree
    tree:add(fields.format, parts[1])
    tree:add(fields.num_fragments, tonumber(parts[2]) or 0)
    tree:add(fields.fragment_num, tonumber(parts[3]) or 0)
    tree:add(fields.msg_id, parts[4]) -- This field may be empty, but we still add it to the tree
    tree:add(fields.channel, parts[5])
    tree:add(fields.payload, parts[6])
    tree:add(fields.fill_bits, tonumber(parts[7]) or 0)
    
    if checksum then
        tree:add(fields.checksum, checksum)
        
        -- Validate checksum
        local calculatedChecksum = 0
        local checksumPart = nmeaString:match("^(.-)[*]")
        
        if checksumPart then
            for i = 2, #checksumPart do  -- Skip the first character (!)
                calculatedChecksum = bit.bxor(calculatedChecksum, string.byte(string.sub(checksumPart, i, i)))
            end
            
            local hexChecksum = string.format("%02X", calculatedChecksum)
            if hexChecksum ~= string.upper(checksum) then
                tree:add_proto_expert_info(ais_checksum_error, "Checksum mismatch: calculated " .. hexChecksum .. ", received " .. checksum)
                return false
            end
        end
    end
    
    if parts[1] ~= "!AIVDM" and parts[1] ~= "!AIVDO" then
        tree:add_proto_expert_info(ais_invalid_format, "Not an AIS message")
        return false
    end
    
    if ais_proto.prefs.enable_reassembly and tonumber(parts[2]) > 1 then
        -- Multi-part message
        local totalFragments = tonumber(parts[2])
        local fragmentNumber = tonumber(parts[3])
        local messageId = parts[4]
        local payload = parts[6]
        
        -- Create a unique identifier for this multipart message
        local msgKey = tostring(pinfo.number) .. "_" .. messageId
        
        if not multipart_cache[msgKey] then
            multipart_cache[msgKey] = {
                fragments = {},
                count = totalFragments,
                received = 0
            }
        end
        
        -- Only add fragment if we haven't seen it before
        if not multipart_cache[msgKey].fragments[fragmentNumber] then
            multipart_cache[msgKey].fragments[fragmentNumber] = payload
            multipart_cache[msgKey].received = multipart_cache[msgKey].received + 1
        end
        
        if multipart_cache[msgKey].received > multipart_cache[msgKey].count then
            -- Something went wrong, reset the cache for this message
            multipart_cache[msgKey] = nil
            tree:add_proto_expert_info(ais_invalid_format, 
                "Invalid fragment count: received more fragments than expected")
            return false
        end
        
        if multipart_cache[msgKey].received == multipart_cache[msgKey].count then
            -- We have all fragments, combine them
            local combinedPayload = ""
            for i = 1, totalFragments do
                combinedPayload = combinedPayload .. multipart_cache[msgKey].fragments[i]
            end
            
            local subtree = tree:add(ais_proto, combinedPayload, "AIS Combined Payload")
            dissect_ais_payload(combinedPayload, subtree)
            
            pinfo.cols.protocol = "AIS"
            pinfo.cols.info = messageTypes[getBits(combinedPayload, 0, 6)] or "Unknown AIS Message"
            
            -- Clear the cache for this message
            multipart_cache[msgKey] = nil
            return true
        else
            tree:add_proto_expert_info(ais_multipart_incomplete, 
                "Incomplete multipart message: " .. multipart_cache[msgKey].received .. 
                " of " .. multipart_cache[msgKey].count .. " fragments")
            
            pinfo.cols.protocol = "AIS"
            pinfo.cols.info = "AIS Multipart Message (fragment " .. fragmentNumber .. 
                              " of " .. totalFragments .. ")"
            return true
        end
    elseif parts[2] == "1" and parts[3] == "1" then
        -- Single part message, decode directly
        local payload = parts[6]
        local subtree = tree:add(ais_proto, payload, "AIS Payload")
        dissect_ais_payload(payload, subtree)
        pinfo.cols.protocol = "AIS"
        pinfo.cols.info = messageTypes[getBits(payload, 0, 6)] or "Unknown AIS Message"
        return true
    end
    
    return false
end

-- Main dissector function
function ais_proto.dissector(buffer, pinfo, tree)
    -- Make sure we have enough data
    if buffer:len() == 0 then return end
    
    -- Try to extract NMEA sentence
    local nmeaString = buffer:raw(0, buffer:len())
    
    -- Create the AIS protocol tree item
    local subtree = tree:add(ais_proto, buffer(), "Automatic Identification System")
    
    -- Parse the NMEA string
    if parse_nmea(nmeaString, pinfo, subtree) then
        -- Successfully parsed
        return buffer:len()
    end
    
    -- If we failed to parse directly, try to find NMEA sentences in the buffer
    local offset = 0
    local found = false
    
    while offset < buffer:len() do
        local nmeaStart = string.find(nmeaString, "!AIVD[MO]", offset)
        if not nmeaStart then break end
        
        local nmeaEnd = string.find(nmeaString, "\r\n", nmeaStart) or string.find(nmeaString, "\n", nmeaStart)
        if not nmeaEnd then nmeaEnd = buffer:len() end
        
        local singleNmea = string.sub(nmeaString, nmeaStart, nmeaEnd - 1)
        local nmeaSubtree = subtree:add(ais_proto, buffer(nmeaStart, nmeaEnd - nmeaStart), "AIS NMEA Sentence")
        
        if parse_nmea(singleNmea, pinfo, nmeaSubtree) then
            found = true
        end
        
        offset = nmeaEnd
    end
    
    if found then
        return buffer:len()
    end
    
    -- Could not find a valid AIS message
    return 0
end

-- Add to the protocol preferences
ais_proto.prefs.enable_reassembly = Pref.bool("enable_reassembly", true, "Reassemble fragmented messages")

-- Register dissector by name
local udp_port_table = DissectorTable.get("udp.port")
local tcp_port_table = DissectorTable.get("tcp.port")

-- Register for common AIS ports
udp_port_table:add(10110, ais_proto) -- NMEA Standard 0183 messages

-- Create a heuristic dissector for any UDP or TCP packet
function heuristic_checker(buffer, pinfo, tree)
    local potential_nmea = buffer:raw(0, buffer:len())
    
    -- Look for AIVDM or AIVDO strings which indicate AIS data
    if string.find(potential_nmea, "!AIVD[MO]") then
        ais_proto.dissector(buffer, pinfo, tree)
        return true
    end
    
    return false
end

-- Register as heuristic dissector for both UDP and TCP
ais_proto:register_heuristic("udp", heuristic_checker)
ais_proto:register_heuristic("tcp", heuristic_checker)

-- Return the protocol for reference
return ais_proto