description = [[
Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.
 It also detects if the server allows any called Application Entity Title or not.

The script responds with the message "Called AET check enabled" when the association request
 is rejected due configuration. This value can be bruteforced.

C-ECHO requests are commonly known as DICOM ping as they are used to test connectivity.
Normally, a 'DICOM ping' is formed as follows:
* Client -> A-ASSOCIATE request -> Server
* Server -> A-ASSOCIATE ACCEPT/REJECT -> Client
* Client -> C-ECHO request -> Server
* Server -> C-ECHO response -> Client
* Client -> A-RELEASE request -> Server
* Server -> A-RELEASE response -> Client

For this script we only send the A-ASSOCIATE request and look for the success code
 in the response as it seems to be a reliable way of detecting DICOM servers.
]]

---
-- @usage nmap -p4242 --script dicom-ping <target>
-- @usage nmap -sV --script dicom-ping <target>
-- 
-- @output
-- PORT     STATE SERVICE REASON
-- 4242/tcp open  dicom   syn-ack
-- | dicom-ping: 
-- |   dicom: DICOM Service Provider discovered!
-- |   config: Any AET is accepted (Insecure)
-- |   vendor: Orthanc
-- |_  version: 1.11.0
--
-- @xmloutput
-- <script id="dicom-ping" output="&#xa;  dicom: DICOM Service Provider discovered!&#xa;
--   config: Any AET is accepted (Insecure)&#xa;
--   vendor: Orthanc&#xa;
--   version: 1.11.0"><elem key="dicom">DICOM Service Provider discovered!</elem>
-- <elem key="config">Any AET is accepted (Insecure)</elem>
-- <elem key="vendor">Orthanc</elem>
-- <elem key="version">1.11.0</elem>
-- </script>
---

author = "Paulino Calderon <calderon()calderonpale.com>, Tyler M <tmart23()gmail.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe", "auth"}

local shortport = require "shortport"
local dicom = require "dicom"
local stdnse = require "stdnse"
local nmap = require "nmap"
local http = require "http"

portrule = shortport.port_or_service({104, 2345, 2761, 2762, 4242, 11112}, "dicom", "tcp", "open")

-- Extract version from version string based on vendor
local function extract_clean_version(version_str, vendor)
  if not version_str then return nil end
  
  if vendor == "DCMTK" then
    -- Common DCMTK version format: OFFIS_DCMTK_362 -> 3.6.2
    local major, minor, patch = version_str:match("DCMTK_(%d)(%d+)(%d)")
    if major and minor and patch then
      return string.format("%s.%s.%s", major, minor, patch)
    end
    
    -- Alternative format: DCMTK_364
    major, minor, patch = version_str:match("DCMTK_(%d)(%d)(%d)")
    if major and minor and patch then
      return string.format("%s.%s.%s", major, minor, patch)
    end
  end
  
  -- Try standard version format: x.y.z
  local version = version_str:match("(%d+%.%d+%.%d+)")
  if version then
    return version
  end
  
  -- If all else fails, return as is
  return version_str
end

action = function(host, port)
  local output = stdnse.output_table()
  
  -- Try association
  local dcm_status, err, version, vendor = dicom.associate(host, port)
  
  -- Handle association rejection
  if dcm_status == false then
    stdnse.debug1("Association failed: %s", err or "Unknown error")
    if err == "ASSOCIATE REJECT received" then
      port.version.name = "dicom"
      nmap.set_port_version(host, port)
  
      output.dicom = "DICOM Service Provider discovered!"
      output.config = "Called AET check enabled"
    end
    return output
  end
  
  -- Association successful
  port.version.name = "dicom"
  nmap.set_port_version(host, port)

  output.dicom = "DICOM Service Provider discovered!"
  output.config = "Any AET is accepted (Insecure)"

  -- Add version information if available
  if version then
    stdnse.debug1("Detected DICOM version string: %s", version)
    local clean_version = extract_clean_version(version, vendor)
    if clean_version then
      stdnse.debug1("Cleaned version: %s", clean_version)
      output.version = clean_version
    else
      output.version = version
    end
  end

  -- Add vendor information if available
  if vendor then
    stdnse.debug1("Detected DICOM vendor: %s", vendor)
    output.vendor = vendor
    
    -- Orthanc-specific REST check
    if vendor == "Orthanc" then
      stdnse.debug1("Detected Orthanc, trying REST API for version...")
      
      -- Try default Orthanc port first (8042)
      local ports_to_try = {8042, port.number}
      
      for _, test_port in ipairs(ports_to_try) do
        local response = http.get(host, test_port, "/system", {timeout=3000})
        if response.status == 200 then
          local ver = response.body:match('"Version"%s*:%s*"([%d.]+)"')
          if ver then
            stdnse.debug1("Found Orthanc version via REST: %s", ver)
            output.version = ver
            output.vendor = "Orthanc"
            output.notes = "Version confirmed via REST API"
            break
          end
        end
      end
    end
  end

  return output
end