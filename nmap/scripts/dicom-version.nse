description = [[
Detects DICOM implementation version by analyzing the Association Accept PDU response.
Complements dicom-ping and dicom-bruteforce scripts when the AE title is known.
]]
author = "Tyler M"
license = "Same as Nmap--See https://nmap.org"
categories = {"version", "safe"}

local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local dicom = require "dicom"
local string = require "string"
local bin = require "bin"
local table = require "table"

portrule = shortport.service({"dicom", "vrml-multi-use"})

-- Helper function to dump binary data for debugging
local function hexdump(data, indent)
  indent = indent or ""
  local output = {}
  for i = 1, #data do
    if (i - 1) % 16 == 0 then
      table.insert(output, indent .. string.format("%08x: ", i - 1))
    end
    table.insert(output, string.format("%02x ", string.byte(data, i)))
    if i % 16 == 0 then table.insert(output, "\n") end
  end
  if #data % 16 ~= 0 then table.insert(output, "\n") end
  return table.concat(output)
end

action = function(host, port)
    local output = stdnse.output_table()
    local debug_info = {}
    
    -- Customizable AE Titles (with defaults)
    local called_aet = stdnse.get_script_args(SCRIPT_NAME .. ".called_aet") or "ORTHANC"
    local calling_aet = stdnse.get_script_args(SCRIPT_NAME .. ".calling_aet") or "NMAP_SCU"
    
    stdnse.debug1("Attempting DICOM association with %s:%d (Called AET: %s, Calling AET: %s)", 
                  host.ip, port.number, called_aet, calling_aet)
    
    -- Try to establish association with DICOM server
    local status, dcm_or_err = dicom.associate(host, port, calling_aet, called_aet)
    
    if not status then
        stdnse.debug1("DICOM association failed: %s", dcm_or_err)
        return nil
    end
    
    -- Receive the Association Accept PDU
    local response = dcm_or_err.socket:receive_bytes(4096)
    dcm_or_err.socket:close()
    
    if not response or #response < 10 then
        stdnse.debug1("Received empty or too short response")
        return nil
    end
    
    -- Log the received data
    table.insert(debug_info, string.format("DICOM: receive() read %d bytes", #response))
    
    -- Check PDU type (should be 2 for Association Accept)
    local pdu_type = string.byte(response, 1)
    local pdu_length = string.unpack(">I4", response:sub(2, 5))
    
    table.insert(debug_info, string.format("PDU Type:%d Length:%d", pdu_type, pdu_length))
    
    if pdu_type ~= 2 then
        stdnse.debug1("Not an ASSOCIATE ACCEPT PDU (type %d)", pdu_type)
        nmap.set_port_debug(host, port, table.concat(debug_info, "\n"))
        return nil
    end
    
    table.insert(debug_info, "ASSOCIATE ACCEPT message found!")
    
    -- Detailed debug dump of the PDU
    stdnse.debug2("PDU Hex Dump:\n%s", hexdump(response))
    
    -- Process the User Information items
    -- Skip PDU header (6 bytes) and fixed fields
    local user_info_offset = nil
    local i = 74  -- Start after fixed header and AE fields
    
    -- Search for User Information item (type 0x50)
    while i < #response do
        local item_type = string.byte(response, i)
        stdnse.debug2("Checking item at offset %d, type 0x%02x", i, item_type or 0)
        
        if item_type == 0x50 then  -- User Information
            user_info_offset = i
            stdnse.debug2("Found User Information item at offset %d", i)
            break
        end
        
        -- Skip item header (4 bytes) and item content
        if item_type then
            i = i + 2  -- Skip item type and reserved
            local item_len = string.unpack(">I2", response:sub(i, i+1))
            i = i + 2 + item_len  -- Skip length and content
        else
            break
        end
    end
    
    if not user_info_offset then
        stdnse.debug1("No User Information item found in PDU")
        nmap.set_port_debug(host, port, table.concat(debug_info, "\n"))
        return nil
    end
    
    -- Parse User Information subitems
    i = user_info_offset + 4  -- Skip item type, reserved, and length
    local user_info_length = string.unpack(">I2", response:sub(user_info_offset+2, user_info_offset+3))
    local end_of_user_info = user_info_offset + 4 + user_info_length
    
    table.insert(debug_info, string.format("User Info at offset %d, length %d", user_info_offset, user_info_length))
    
    while i < end_of_user_info do
        local sub_item_type = string.byte(response, i)
        local sub_item_length = string.unpack(">I2", response:sub(i+2, i+3))
        
        stdnse.debug2("User Info subitem: type 0x%02x, length %d", sub_item_type or 0, sub_item_length or 0)
        
        if sub_item_type == 0x55 then  -- Implementation Version Name
            local version_str = response:sub(i+4, i+3+sub_item_length):gsub("%z", "")
            output["Implementation Version"] = version_str
            table.insert(debug_info, string.format("Found Implementation Version: %s", version_str))
            break
        elseif sub_item_type == 0x52 then  -- Implementation Class UID
            local class_uid = response:sub(i+4, i+3+sub_item_length):gsub("%z", "")
            output["Implementation Class UID"] = class_uid
            table.insert(debug_info, string.format("Found Implementation Class UID: %s", class_uid))
        end
        
        i = i + 4 + sub_item_length  -- Move to next subitem
    end
    
    -- Set debug info
    nmap.set_port_debug(host, port, table.concat(debug_info, "\n"))
    
    -- Return results if any were found
    if next(output) then
        return output
    else
        return "DICOM server detected, but no implementation version information available"
    end
end