-- Analyst Hunt Pack

-------------------------------------------------
-- Configurable values 
-------------------------------------------------

SPLUNK_URL = "https://splunk:8443/en-US/appsearch/search?q="
ROBTEX_URL = "https://www.robtex.com/dns-lookup/"


-------------------------------------------------
-- General Helper Functions 
-------------------------------------------------
local function win_shell_quote(s)
    s = string.gsub(s, "\\", "\\\\")
    s = string.gsub(s, '"', '\"')
    return '"' .. s .. '"'
end

local function shell_quote(s)
    return "'" .. string.gsub(s, "'", "'\"'\"'") .. "'"
end

local function string_quote(s)
    s = string.gsub(s, "\\", "\\\\")
    s = string.gsub(s, '"', '\"')
    return s
end

-- Note: Currently only supports windows!
local function run_in_terminal(cmd, ...)
    local args = {...};

    -- Detect the client's operating system
    -- Mac is currently unsupported
    -- According to https://www.quora.com/What-is-the-terminal-command-to-open-new-terminal-window-in-Mac , the command is:
    -- open -a Terminal -n
    
    local os = 'unknown'
    if (package.config:sub(1,1) == '\\') then
        os = 'win'
    else
        os = 'nix'
    end

    -- Launch a terminal with the specified command, OS-specific
    if (os == "win") then
        -- Windows Example: start cmd /k ping "google.com"
        local arg_string = ""

        for i, arg in ipairs(args) do
            arg_string = arg_string .. ' ' .. win_shell_quote(arg)
        end

        win_cmd = 'start cmd /k ' .. cmd .. arg_string
        print(win_cmd)
        os.execute(win_cmd)
    else
        local command_string = cmd
        for i, arg in ipairs(args) do
            command_string = command_string .. ' ' .. shell_quote(arg)
        end

        ubuntu_cmd = 'gnome-terminal -e "bash -c \\"' .. string_quote(command_string) .. '; exec bash\\""'
        print(ubuntu_cmd)
        os.execute(ubuntu_cmd)
    end

end

-------------------------------------------------
-- HTTP Analysis 
-------------------------------------------------

local function lookup_ssl_labs(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            browser_open_url('https://www.ssllabs.com/ssltest/analyze.html?d=' .. field.value)
            break
        end
    end
end

local function search_google_http_host(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            browser_open_url('https://www.google.com/search?q=' .. field.value)
            break
        end
    end
end

local function nslookup(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            run_in_terminal('nslookup', field.value)
            break
        end
    end
end

local function search_host_in_robtex(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            	browser_open_url(ROBTEX_URL .. field.value)
            break
        end
    end
end

local function search_http_host_in_shodan(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            	browser_open_url("https://www.shodan.io/search?query=" .. field.value)
            break
        end
    end
end

local function search_host_in_splunk(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            	browser_open_url(SPLUNK_URL .. 'index=* sourcetype=* ' .. field.value)
            break
        end
    end
end

local function examine_url_in_unfurl(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.request.full_uri') then
            	browser_open_url("https://dfir.blog/unfurl/?url=" .. field.value)
            break
        end
    end
end

local function search_url_in_urlvoid(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.request.full_uri') then
            	browser_open_url("https://www.urlvoid.com/scan/google.com/" .. field.value)
            break
        end
    end
end

local function search_url_in_virustotal(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.request.full_uri') then
            	browser_open_url("https://www.virustotal.com/gui/search/" .. field.value)
            break
        end
    end
end


-------------------------------------------------
-- IP Address Analysis 
-------------------------------------------------

-- Traffic from this source IP

local function search_destip_in_robtex(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'ip.dst') then
            	browser_open_url(ROBTEX_URL .. field.display)
            break
        end
    end
end

local function search_destip_in_shodan(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'ip.dst') then
            	browser_open_url("https://www.shodan.io/host/" .. field.value)
            break
        end
    end
end

local function search_destip_in_splunk(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'ip.dst') then
            	browser_open_url(SPLUNK_URL .. 'index=* sourcetype=* ' .. field.display)
            break
        end
    end
end

-------------------------------------------------
-- SMTP Analysis 
-------------------------------------------------

-- Emails with this subject
-- Emails from this sender
-- Emails from this mailserver



-------------------------------------------------
-- DNS Analysis 
-------------------------------------------------

local function search_google_dns_query(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'dns.qry.name') then
            browser_open_url('https://www.google.com/search?q=' .. field.value)
            break
        end
    end
end

local function search_mxtoolbox_dns_query(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'dns.qry.name') then
            browser_open_url('https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=dns:' .. field.value)
            break
        end
    end
end

local function search_robtex_dns_query(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'dns.qry.name') then
            browser_open_url('https://www.robtex.com/dns-lookup/' .. field.value)
            break
        end
    end
end

-------------------------------------------------
-- Register all packet menus 
-------------------------------------------------

-- HTTP
register_packet_menu("HTTP/HTTP Host on SSL Labs", lookup_ssl_labs, "http.host");
register_packet_menu("HTTP/HTTP Host on Google", search_google_http_host, "http.host");
register_packet_menu("HTTP/nslookup HTTP Host", nslookup, "http.host");
register_packet_menu("HTTP/HTTP Host in Robtex", search_host_in_robtex, "http.host");
register_packet_menu("HTTP/HTTP Host in Shodan", search_http_host_in_shodan, "http.host");
register_packet_menu("HTTP/HTTP Host in Splunk", search_host_in_splunk, "http.host");
register_packet_menu("HTTP/HTTP URL in URL Void", search_url_in_urlvoid, "http.request.full_uri");
register_packet_menu("HTTP/HTTP URL in VirusTotal", search_host_in_splunk, "http.request.full_uri");
register_packet_menu("HTTP/HTTP URL in Unfurl", examine_url_in_unfurl, "http.request.full_uri");


-- IP
register_packet_menu("IP/Destination IP in Robtex", search_destip_in_robtex, "ip.dst");
register_packet_menu("IP/Destination IP in Shodan", search_destip_in_shodan, "ip.dst");
register_packet_menu("IP/Destination IP in Splunk", search_destip_in_splunk, "ip.dst");


-- DNS
register_packet_menu("DNS/DNS Host on Google", search_google_dns_query, "dns.qry.name");
register_packet_menu("DNS/DNS Host on MXToolbox", search_mxtoolbox_dns_query, "dns.qry.name");
register_packet_menu("DNS/DNS Host on Robtex", search_robtex_dns_query, "dns.qry.name");

