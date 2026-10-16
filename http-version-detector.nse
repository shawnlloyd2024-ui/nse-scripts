
description = [[
Detects the HTTP server software, version,
server banner and port information using
multi-source HTTP fingerprinting.
]]

author = "Shawn"
license = "Same as Nmap"
categories = {"discovery", "safe"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)

    -- Send a GET request
    local response = http.get(host, port, "/")

    if not response then
        return "Unable to connect to the HTTP service."
    end

    -- Send a HEAD request
    local head = http.head(host, port, "/")

    -- Send an OPTIONS request
    local options = http.generic_request(
        host, port, "OPTIONS", "/"
    )

    -- Extract server headers
    local server = response.header["server"] or "Unknown"
    local head_server = "Unknown"
    local options_server = "Unknown"

    if head and head.header then
        head_server = head.header["server"] or "Unknown"
    end

    if options and options.header then
        options_server = options.header["server"] or "Unknown"
    end

    -- Detect product and version
    local product = "Unknown"
    local version = "Unknown"

    local p, v = server:match("([%w%-]+)/([%d%.]+)")

    if p then
        product = p
    end

    if v then
        version = v
    end

    -- Detect HTML signatures
    local signature = "Unknown"

    if response.body then
        if response.body:find("Apache2 Debian Default Page", 1, true) then
            signature = "Apache Default Page"
        elseif response.body:find("Welcome to nginx", 1, true) then
            signature = "Nginx Default Page"
        elseif response.body:find("IIS Windows Server", 1, true) then
            signature = "Microsoft IIS"
        elseif response.body:find("LiteSpeed", 1, true) then
            signature = "LiteSpeed"
        end
    end

    -- Extract generator meta tag
    local generator = "None"

    if response.body then
        local g = response.body:match(
            '<meta%s+name="generator"%s+content="(.-)"'
        )

        if g then
            generator = g
        end
    end

    -- Calculate confidence score
    local score = 0

    if server ~= "Unknown" then
        score = score + 40
    end

    if server == head_server then
        score = score + 20
    end

    if server == options_server then
        score = score + 20
    end

    if signature ~= "Unknown" then
        score = score + 20
    end

    local confidence = tostring(score) .. "%"

    -- Check header consistency
    local consistency = "PASS"

    if server ~= head_server or server ~= options_server then
        consistency = "PARTIAL"
    end

    -- Format the output
    local output = stdnse.output_table()

    output["Target"] = host.ip
    output["Port"] = port.number
    output["Service"] = port.service or "http"
    output["Product"] = product
    output["Version"] = version
    output["Server Header"] = server
    output["HEAD Header"] = head_server
    output["OPTIONS Header"] = options_server
    output["HTML Signature"] = signature
    output["Generator Tag"] = generator
    output["Header Consistency"] = consistency
    output["Confidence Score"] = confidence
    output["Detection Method"] = "Multi-Source Fingerprinting"
    output["Status"] = "HTTP service detected"

    return output
end
