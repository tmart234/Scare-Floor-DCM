---
-- DICOM library
--
-- This library implements (partially) the DICOM protocol. This protocol is used to
-- capture, store and distribute medical images.
--
-- From Wikipedia:
-- The core application of the DICOM standard is to capture, store and distribute
-- medical images. The standard also provides services related to imaging such as
-- managing imaging procedure worklists, printing images on film or digital media
-- like DVDs, reporting procedure status like completion of an imaging acquisition,
-- confirming successful archiving of images, encrypting datasets, removing patient
-- identifying information from datasets, organizing layouts of images for review,
-- saving image manipulations and annotations, calibrating image displays, encoding
-- ECGs, encoding CAD results, encoding structured measurement data, and storing
-- acquisition protocols.
--
-- OPTIONS:
-- *<code>called_aet</code> - If set it changes the called Application Entity Title
--                            used in the requests. Default: ANY-SCP
-- *<code>calling_aet</code> - If set it changes the calling Application Entity Title
--                            used in the requests. Default: ECHOSCU
--
-- @args dicom.called_aet Called Application Entity Title. Default: ANY-SCP
-- @args dicom.calling_aet Calling Application Entity Title. Default: ECHOSCU
-- 
-- @author Paulino Calderon <paulino@calderonpale.com> and Tyler M <tmart234@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

_ENV = stdnse.module("dicom", stdnse.seeall)

local MIN_SIZE_ASSOC_REQ = 68
local MAX_SIZE_PDU = 128000
local MIN_HEADER_LEN = 6
local PDU_NAMES = {}
local PDU_CODES = {}

PDU_CODES =
{
  ASSOCIATE_REQUEST  = 0x01,
  ASSOCIATE_ACCEPT   = 0x02,
  ASSOCIATE_REJECT   = 0x03,
  DATA               = 0x04,
  RELEASE_REQUEST    = 0x05,
  RELEASE_RESPONSE   = 0x06,
  ABORT              = 0x07
}

for i, v in pairs(PDU_CODES) do
  PDU_NAMES[v] = i
end

-- Define vendor UIDs lookup table with patterns
local VENDOR_UID_PATTERNS = {
  {"^1%.2%.276%.0%.7230010%.3%.0%.3%.6%.", "DCMTK"},         -- All DCMTK variants
  {"^1%.4%.3%.6%.1%.4%.1%.78293%.3%.1",    "Orthanc"},       -- Orthanc
  {"^1%.3%.46%.670589%.50%.1%.4",          "Conquest"},      -- Conquest PACS
  {"^1%.2%.40%.0%.13%.1%.1",               "DCM4CHE"},       -- dcm4chee
  {"^1%.2%.840%.113619%.6%.96",            "GE Healthcare"}, -- GE
  {"^1%.2%.840%.113619%.6%.105",           "Philips"},       -- Philips
  {"^1%.3%.12%.2%.1107%.5%.99",            "Siemens Syngo"}  -- Siemens
}

---
-- start_connection(host, port) starts socket to DICOM service
--
-- @param host Host object
-- @param port Port table
-- @return (status, socket) If status is true, socket of DICOM object is set.
--                          If status is false, socket is the error message.
---
function start_connection(host, port)
  local dcm = {}
  local status, err
  dcm['socket'] = nmap.new_socket()

  status, err = dcm['socket']:connect(host, port, "tcp")

  if(status == false) then
    return false, "DICOM: Failed to connect to host: " .. err
  end

  return true, dcm
end

---
-- send(dcm, data) Sends DICOM packet over established socket
--
-- @param dcm DICOM object
-- @param data Data to send
-- @return status True if data was sent correctly, otherwise false and error message is returned.
---
function send(dcm, data) 
  local status, err
  stdnse.debug2("DICOM: Sending DICOM packet (%d)", #data)
  if dcm['socket'] then
    status, err = dcm['socket']:send(data)
    if status == false then
      return false, err
    end
  else 
    return false, "No socket found. Check your DICOM object"
  end
  return true
end

---
-- receive(dcm) Reads DICOM packets over an established socket
--
-- @param dcm DICOM object
-- @return (status, data) Returns data if status true, otherwise data is the error message.
---
function receive(dcm)
  local status, data = dcm['socket']:receive()
  if status == false then
    return false, data
  end
  stdnse.debug1("DICOM: receive() read %d bytes", #data)
  return true, data
end

---
-- pdu_header_encode(pdu_type, length) encodes the DICOM PDU header
--
-- @param pdu_type PDU type as ann unsigned integer
-- @param length Length of the DICOM message
-- @return (status, dcm) If status is true, the DICOM object with the header set is returned.
--                       If status is false, dcm is the error message.
---
function pdu_header_encode(pdu_type, length)
  -- Some simple sanity checks, we do not check ranges to allow users to create malformed packets.
  if not(type(pdu_type)) == "number" then
    return false, "PDU Type must be an unsigned integer. Range:0-7"
  end
  if not(type(length)) == "number" then
    return false, "Length must be an unsigned integer."
  end

  local header = string.pack("<B >B I4",
                            pdu_type, -- PDU Type ( 1 byte - unsigned integer in Big Endian )
                            0,        -- Reserved section ( 1 byte that should be set to 0x0 )
                            length)   -- PDU Length ( 4 bytes - unsigned integer in Little Endian)
  if #header < MIN_HEADER_LEN then
    return false, "Header must be at least 6 bytes. Something went wrong."
  end
   return true, header
end

---
-- parse_implementation_version(data) Extracts implementation version and UID from DICOM response
--
-- @param data DICOM response data
-- @return version, uid Implementation version string and UID
---
function parse_implementation_version(data)
  stdnse.debug3("Parsing implementation version from response of length %d", #data)
  
  if #data < 74 then -- Minimum length for a response with user info
    stdnse.debug1("Response too short for version parsing: %d bytes", #data)
    return nil, nil
  end
  
  -- Start after the fixed association header (68 bytes)
  local offset = 68
  local version, uid = nil, nil
  
  -- Find the User Information item (type 0x50)
  while offset < #data - 4 do
    local item_type = string.byte(data, offset + 1)
    
    if item_type == 0x50 then -- User Information
      stdnse.debug2("Found User Information at offset %d", offset)
      
      -- Get item length
      local _, item_length = string.unpack(">I2", data, offset + 3)
      local item_end = offset + 4 + item_length
      offset = offset + 4 -- Move past item header
      
      -- Search for implementation items in user info
      while offset < item_end - 4 and offset < #data - 4 do
        local sub_type = string.byte(data, offset + 1)
        local _, sub_length = string.unpack(">I2", data, offset + 3)
        
        -- Sanity check on length
        if sub_length > 64 or offset + 4 + sub_length > #data then
          stdnse.debug1("Invalid sub-item length: %d at offset %d", sub_length, offset)
          break
        end
        
        if sub_type == 0x52 then -- Implementation Class UID
          uid = string.sub(data, offset + 5, offset + 4 + sub_length)
          uid = uid:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "")
          stdnse.debug2("Found Implementation UID: %s", uid)
        elseif sub_type == 0x55 then -- Implementation Version
          version = string.sub(data, offset + 5, offset + 4 + sub_length)
          version = version:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "")
          stdnse.debug2("Found Implementation Version: %s", version)
        end
        
        offset = offset + 4 + sub_length
      end
      break
    else
      -- Skip to next item
      local _, item_length = string.unpack(">I2", data, offset + 3)
      offset = offset + 4 + item_length
    end
  end
  
  return version, uid
end

---
-- parse_vendor_from_uid(uid) Gets vendor name from the UID using pattern matching
--
-- @param uid Implementation UID string
-- @return vendor Vendor name or nil if unknown
-- @return version_part Optional version part extracted from the UID
---
function parse_vendor_from_uid(uid)
  if not uid then return nil end
  
  -- Clean up UID string
  uid = uid:gsub("%z", ""):gsub("^%s+", ""):gsub("%s+$", "")
  
  stdnse.debug1("Looking up vendor for UID: '%s'", uid)
  
  -- Check against patterns
  for _, pattern_info in ipairs(VENDOR_UID_PATTERNS) do
    local pattern, vendor = pattern_info[1], pattern_info[2]
    stdnse.debug2("Checking pattern: %s for vendor: %s", pattern, vendor)
    
    if uid:match(pattern) then
      stdnse.debug1("Found matching vendor: %s for UID: %s", vendor, uid)
      
      -- For DCMTK, try to extract version information from the UID
      if vendor == "DCMTK" then
        local version_part = uid:match("^1%.2%.276%.0%.7230010%.3%.0%.3%.6%.(%d+)$")
        if version_part then
          stdnse.debug1("Extracted DCMTK version info from UID: %s", version_part)
          return vendor, version_part
        end
      end
      
      -- Check for Orthanc UID patterns
      if vendor == "Orthanc" then
        stdnse.debug1("Detected Orthanc from UID")
        return vendor
      end
      
      return vendor
    end
  end
  
  return nil
end

---
-- associate(host, port) Attempts to associate to a DICOM Service Provider by sending an A-ASSOCIATE request.
--
-- @param host Host object
-- @param port Port object
-- @return (status, dcm, version, vendor) If status is true, version and vendor info is returned.
--                       If status is false, dcm is the error message.
---
function associate(host, port, calling_aet, called_aet)
  local application_context = ""
  local presentation_context = ""
  local userinfo_context = ""
  
  local status, dcm = start_connection(host, port)
  if status == false then
    return false, dcm
  end
  
  local application_context_name = "1.2.840.10008.3.1.1.1"
  application_context = string.pack(">B B s2",
                                    0x10,
                                    0x0,
                                    application_context_name)
  
  local abstract_syntax_name = "1.2.840.10008.1.1"
  local transfer_syntax_name = "1.2.840.10008.1.2"
  presentation_context = string.pack(">B B I2 B B B B B B s2 B B s2",
                                    0x20, -- Presentation context type ( 1 byte )
                                    0x0,  -- Reserved ( 1 byte )
                                    0x2e,   -- Item Length ( 2 bytes )
                                    0x1,  -- Presentation context id ( 1 byte )
                                    0x0,0x0,0x0,  -- Reserved ( 3 bytes )
                                    0x30, -- Abstract Syntax Tree ( 1 byte )
                                    0x0,  -- Reserved ( 1 byte )
                                    abstract_syntax_name,
                                    0x40, -- Transfer Syntax ( 1 byte )
                                    0x0,  -- Reserved ( 1 byte )
                                    transfer_syntax_name)
                                    
  local implementation_id = "1.2.276.0.7230010.3.0.3.6.2"
  local implementation_version = "OFFIS_DCMTK_362"
  userinfo_context = string.pack(">B B I2 B B I2 I4 B B s2 B B s2",
                                0x50,    -- Type 0x50 (1 byte)
                                0x0,     -- Reserved ( 1 byte )
                                0x3a,    -- Length ( 2 bytes )
                                0x51,    -- Type 0x51 ( 1 byte) 
                                0x0,     -- Reserved ( 1 byte)
                                0x04,     -- Length ( 2 bytes )
                                0x4000,   -- DATA ( 4 bytes )
                                0x52,    -- Type 0x52 (1 byte)
                                0x0,
                                implementation_id,
                                0x55,
                                0x0,
                                implementation_version)
  
  local called_ae_title = called_aet or stdnse.get_script_args("dicom.called_aet") or "ANY-SCP"
  local calling_ae_title = calling_aet or stdnse.get_script_args("dicom.calling_aet") or "ECHOSCU"
  if #called_ae_title > 16 or #calling_ae_title > 16 then
    return false, "Calling/Called Application Entity Title must be less than 16 bytes"
  end
  called_ae_title = ("%-16s"):format(called_ae_title)
  calling_ae_title = ("%-16s"):format(calling_ae_title)

 -- ASSOCIATE request
  local assoc_request = string.pack(">I2 I2 c16 c16 c32",
                                  0x1, -- Protocol version ( 2 bytes )
                                  0x0, -- Reserved section ( 2 bytes that should be set to 0x0 )
                                  called_ae_title, -- Called AE title ( 16 bytes)
                                  calling_ae_title, -- Calling AE title ( 16 bytes)
                                  "") -- Reserved section ( 32 bytes set to 0x0 )
                                  .. application_context
                                  .. presentation_context
                                  .. userinfo_context
 
  local status, header = pdu_header_encode(PDU_CODES["ASSOCIATE_REQUEST"], #assoc_request)

  -- Something might be wrong with our header
  if status == false then 
    return false, header
  end

  assoc_request = header .. assoc_request
 
  stdnse.debug2("PDU len minus header:%d", #assoc_request-#header)
  if #assoc_request < MIN_SIZE_ASSOC_REQ then
    return false, string.format("ASSOCIATE request PDU must be at least %d bytes and we tried to send %d.", MIN_SIZE_ASSOC_REQ, #assoc_request)
  end 
  local status, err = send(dcm, assoc_request)
  if status == false then
    return false, string.format("Couldn't send ASSOCIATE request:%s", err)
  end
  status, err = receive(dcm)
  if status == false then
    return false, string.format("Couldn't read ASSOCIATE response:%s", err)
  end

  local resp_type, _, resp_length = string.unpack(">B B I4", err)
  stdnse.debug1("PDU Type:%d Length:%d", resp_type, resp_length)
  if resp_type == PDU_CODES["ASSOCIATE_ACCEPT"] then
    stdnse.debug1("ASSOCIATE ACCEPT message found!")
    local version, uid = parse_implementation_version(err)
    local vendor, uid_version = parse_vendor_from_uid(uid)
    
    -- If we didn't get a version from implementation version but got version info from UID
    if not version and uid_version and vendor == "DCMTK" then
      -- Convert UID version number to DCMTK version format
      -- For example, if UID ends with "6", it could be DCMTK 3.6.x
      if uid_version == "0" then
        version = "OFFIS_DCMTK_360"
      elseif uid_version == "2" then
        version = "OFFIS_DCMTK_362"
      elseif uid_version == "4" then
        version = "OFFIS_DCMTK_364"
      elseif uid_version == "6" then
        version = "OFFIS_DCMTK_366"
      else
        version = "OFFIS_DCMTK_" .. uid_version
      end
      stdnse.debug1("Generated version from UID: %s", version)
    end
    
    stdnse.debug1("Version: %s, UID: %s, Vendor: %s, UID Version: %s", 
                  version or "nil", 
                  uid or "nil", 
                  vendor or "nil",
                  uid_version or "nil")
    
    return true, nil, version, vendor
  elseif resp_type == PDU_CODES["ASSOCIATE_REJECT"] then
    stdnse.debug1("ASSOCIATE REJECT message found!")
    return false, "ASSOCIATE REJECT received"
  else
    return false, "Received unknown response"
  end
end

function send_pdata(dicom, data)
  local status, header = pdu_header_encode(PDU_CODES["DATA"], #data)
  if status == false then
    return false, header
  end
  local err
  status, err = send(dicom, header .. data)
  if status == false then
    return false, err
  end
end

return _ENV