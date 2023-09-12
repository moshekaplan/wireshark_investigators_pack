-- Analyst Investigators Pack

-------------------------------------------------
-- Configurable values 
-------------------------------------------------

-- Uncomment and set this to your Splunk server to 
-- enable Splunk-based actions
-- SPLUNK_URL = "https://splunk:8443/en-US/appsearch/search?q="

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
    -- According to https://www.quora.com/What-is-the-terminal-command-to-open-new-terminal-window-in-Mac ,
    -- the command for Mac is:
    -- open -a Terminal -n
    -- and for Ubuntu,
    -- ubuntu_cmd = 'gnome-terminal -e "bash -c \\"' .. string_quote(command_string) .. '; exec bash\\""'
    
    local local_os = 'unknown'
    if (package.config:sub(1,1) == '\\') then
        local_os = 'win'
    else
        local_os = 'nix'
    end

    -- Launch a terminal with the specified command, OS-specific
    if (local_os == "win") then
        -- Windows Example: start cmd /k ping "google.com"
        local arg_string = ""

        for i, arg in ipairs(args) do
            arg_string = arg_string .. ' ' .. win_shell_quote(arg)
        end

        win_cmd = 'start cmd /k ' .. cmd .. arg_string
        print(win_cmd)
        os.execute(win_cmd)
    else
        print("Unsupported Operating System")
    end

end

-- Opens a URL with the fieldname's string version of the field appended to the end
-- Useful for accessing field values where the value isn't a string, like ip.src
local function open_url_with_field_display(url, fieldname, fields)
    for i, field in ipairs( fields ) do
        if (field.name == fieldname) then
            browser_open_url(url .. field.display)
            break
        end
    end
end


local function open_url_with_field_value(url, fieldname, fields)
    for i, field in ipairs( fields ) do
        if (field.name == fieldname) then
            browser_open_url(url .. field.value)
            break
        end
    end
end

-- Generates registration functions to open a URl with a field
-- Returns a function which can be used to easily register more functions
-- For example:
-- register_http_host = create_registration_menu_field("HTTP Host", "http.host", "value")
-- register_http_host("Google", "https://www.google.com/search?q=")
local function create_registration_url_with_field(menu_title, fieldname, value_type)
    if (value_type ~= "display" and value_type ~= "value") then
        error("Invalid value type of ".. value_type ". Must be 'display' or 'value'")
    end
    local function register_submenu(submenu_title, url)
        local function generate_host_callback(...)
            local fields = {...};
            if (value_type == "value") then
                return open_url_with_field_value(url, fieldname, fields)
            else
                return open_url_with_field_display(url, fieldname, fields)
            end
        end
        register_packet_menu(menu_title .. "/" .. submenu_title, generate_host_callback, fieldname);
    end
    return register_submenu
end

-------------------------------------------------
-- Splunk Analysis
-------------------------------------------------

local function search_field_value_in_splunk(field_name)
    -- Generates a function to search for a field's
    -- value in Splunk
    local function search_splunk(...)
        local fields = {...};

        for i, field in ipairs( fields ) do
            if (field.name == field_name) then
                    browser_open_url(SPLUNK_URL .. 'index=* sourcetype=* ' .. field.value)
                break
            end
        end
    end
    return search_splunk
end

-------------------------------------------------
-- HTTP Host Analysis
-------------------------------------------------

local function nslookup(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            run_in_terminal('nslookup', field.value)
            break
        end
    end
end

local function ping(...)
    local fields = {...};

    for i, field in ipairs( fields ) do
        if (field.name == 'http.host') then
            run_in_terminal('ping', field.value)
            break
        end
    end
end


-------------------------------------------------
-- IP Address Analysis 
-------------------------------------------------

-- Register a callback for both Source and Dest IPs
local function register_both_src_dest_IP(menu_title, url)

    local function generated_callback_src(...)
        local fields = {...};
        local fieldname = "ip.src"
        return open_url_with_field_display(url, fieldname, fields)
    end
    local function generated_callback_dest(...)
        local fields = {...};
        local fieldname = "ip.dst"
        return open_url_with_field_display(url, fieldname, fields)
    end

    register_packet_menu("IP Dest/" .. menu_title, generated_callback_dest, "ip.dst");
    register_packet_menu("IP Src/" .. menu_title, generated_callback_src, "ip.src");
end

-------------------------------------------------
-- SMTP/IMF Analysis 
-------------------------------------------------

-- Emails with this subject
-- Emails from this sender
-- Emails from this mailserver

local function lookup_spamhaus_imf_from(...)
    fieldname = 'imf.from'
    url = "https://check.spamhaus.org/listed/?searchterm="
    local fields = {...};
    for i, field in ipairs( fields ) do
        if (field.name == fieldname) then
            -- Extract Email address
            email_address = ""
            left_angle_bracket = string.find(field.value, "<")
            if left_angle_bracket ~= nil then
                right_angle_bracket = string.find(string.sub(field.value, left_angle_bracket), ">")
                email_address = string.sub(field.value, left_angle_bracket + 1, left_angle_bracket + right_angle_bracket - 2)
            else
                email_address = field.value
            end
            
            browser_open_url(url .. email_address)
            break
        end
    end
    
end

-------------------------------------------------
-- Register all packet menus 
-------------------------------------------------

-- DNS

register_dns_query_name = create_registration_url_with_field("DNS", "dns.qry.name", "value")
register_dns_query_name("Google for queried host", "https://www.google.com/search?q=")
register_dns_query_name("MXToolbox for queried host", "https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=dns:")
register_dns_query_name("Robtex for queried host", "https://www.robtex.com/dns-lookup/")

-- HTTP Host
register_http_host = create_registration_url_with_field("HTTP Host", "http.host", "value")
register_http_host("Alienvault OTX", "https://otx.alienvault.com/indicator/domain/")
register_http_host("Google", "https://www.google.com/search?q=")
register_packet_menu("HTTP Host/nslookup", nslookup, "http.host");
register_packet_menu("HTTP Host/ping", ping, "http.host");
register_http_host("Robtex", "https://www.robtex.com/dns-lookup/")
register_http_host("Shodan", "https://www.shodan.io/search?query=")
-- Note: This action requires setting the SPLUNK_URL:
if SPLUNK_URL ~= nil then
    register_packet_menu("HTTP Host/Splunk", search_field_value_in_splunk("http.host"), "http.host");
end
register_http_host("SSL Labs", "https://www.ssllabs.com/ssltest/analyze.html?d=")
register_http_host("VirusTotal", "https://www.virustotal.com/gui/domain/")
register_http_host("Whois", "https://www.whois.com/whois/")

-- HTTP URL
register_http_url = create_registration_url_with_field("HTTP URL", "http.request.full_uri", "display")
register_http_url("McAfee Categorization", "https://sitelookup.mcafee.com/en/feedback/url?action=checksingle&product=01-ts&url=");
register_http_url("Unfurl", "https://dfir.blog/unfurl/?url=");
register_http_url("URLVoid", "https://www.urlvoid.com/scan/");

-- IP
register_both_src_dest_IP("ASN lookup", "https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=asn%3a")
register_both_src_dest_IP("IPLocation lookup", "https://www.iplocation.net/ip-lookup?submit=IP+Lookup&query=")
register_both_src_dest_IP("IP Void scan", "https://www.ipvoid.com/scan/")
register_both_src_dest_IP("Shodan search", "https://www.shodan.io/host/")
-- Note: This action requires setting the SPLUNK_URL:
if SPLUNK_URL ~= nil then
    register_both_src_dest_IP("Splunk search", SPLUNK_URL)
end


-- IMF (SMTP)
register_packet_menu("IMF/Spamhaus for email sender", lookup_spamhaus_imf_from, "imf.from");
if SPLUNK_URL ~= nil then
    register_packet_menu("IMF/Splunk search for subject", search_field_value_in_splunk("imf.subject"), "imf.subject");
end
