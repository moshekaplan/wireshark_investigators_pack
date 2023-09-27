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
local function validate_domain_name(domain)
    return string.find(domain, "^%s*[%w%._-]+$") ~= nil
end

local function determine_os(...)
    local local_os = ''
    if (package.config:sub(1,1) == '\\') then
        local_os = 'win'
    else
        local_os = 'nix'
    end
    return local_os
end

local function run_in_terminal(...)
    local cmd_args = {...};
    local local_os = determine_os()

    -- Launch a terminal with the specified command, OS-specific
    if (local_os == "win") then
        -- Windows Example: start cmd /k ping "google.com"
        local arg_string = ""

        for i, arg in ipairs(cmd_args) do
            if (i == 1) then
                arg_string = arg
            else
                arg_string = arg_string .. ' ' .. arg
            end
        end

        win_cmd = 'start cmd /k ' .. arg_string
        print(win_cmd)
        os.execute(win_cmd)
    elseif (local_os == "nix") then
        local arg_string = ""
        for i, arg in ipairs(cmd_args) do
            if (i == 1) then
                arg_string = arg
            else
                arg_string = arg_string .. ' ' .. arg
            end
        end
        local handle = io.popen(arg_string)
        local result = handle:read("*a")
        handle:close()
        local cmd_results = TextWindow.new("Command Results")
        cmd_results:set(result)
    else
        print("Unsupported Operating System")
    end

end


-- Runs a command with the fieldname's value appended to the end
-- Display is useful for accessing field values where the value isn't a string, like ip.src
local function run_cmd_with_field(command, fieldname, fieldtype, fields)
    if (fieldtype ~= "display" and fieldtype ~= "value") then
        error("Invalid fieldtype of ".. fieldtype ". Must be 'display' or 'value'")
    end
    for i, field in ipairs( fields ) do
        if (field.name == fieldname) then
            cmd_arg = ""
            if (fieldtype == "display") then
                cmd_arg = field.display
            elseif (fieldtype == "value") then
                cmd_arg = field.value
            else
                error("Invalid fieldtype")
            end

            if (validate_domain_name(cmd_arg)) then
                run_in_terminal(command, cmd_arg)
            else
                local win = TextWindow.new("Context menu action failed")
                win:set("Error: Could not run command with provided argument " ..
                        "because it failed validation!\n" ..
                        "Requested command was: " .. command .. "\n" ..
                        "Provided argument was: " .. cmd_arg)
            end
            break
        end
    end
end

-- Generates registration functions to run a command with a field
-- Returns a function which can be used to easily register more functions
-- For example:
-- register_http_host_cmd = create_registration_command_with_field("HTTP Host", "http.host", "value")
-- register_http_host_cmd("nslookup", "nslookup")
local function create_registration_command_with_field(menu_title, fieldname, fieldtype)
    if (fieldtype ~= "display" and fieldtype ~= "value") then
        error("Invalid value type of ".. fieldtype ". Must be 'display' or 'value'")
    end
    local function register_submenu(submenu_title, command)
        local function generated_callback(...)
            local fields = {...};
            run_cmd_with_field(command, fieldname, fieldtype, fields)
        end
        register_packet_menu(menu_title .. "/" .. submenu_title, generated_callback, fieldname);
    end
    return register_submenu
end


-- Opens a URL with the fieldname's value appended to the end
-- Display is useful for accessing field values where the value isn't a string, like ip.src
local function open_url_with_field(url, fieldname, fieldtype, fields)
    if (fieldtype ~= "display" and fieldtype ~= "value") then
        error("Invalid fieldtype of ".. fieldtype ". Must be 'display' or 'value'")
    end
    for i, field in ipairs( fields ) do
        if (field.name == fieldname) then
            url_arg = ""
            if (fieldtype == "display") then
                url_arg = field.display
            elseif (fieldtype == "value") then
                url_arg = field.value
            else
                error("Invalid fieldtype")
            end
            browser_open_url(url .. url_arg)
            break
        end
    end
end

-- Generates registration functions to open a URL with the value from a field
-- Returns a function which can be used to easily register more functions
-- For example:
-- register_http_host = create_registration_menu_field("HTTP Host", "http.host", "value")
-- register_http_host("Google", "https://www.google.com/search?q=")
local function create_registration_url_with_field(menu_title, fieldname, fieldtype)
    if (fieldtype ~= "display" and fieldtype ~= "value") then
        error("Invalid fieldtype of ".. fieldtype ". Must be 'display' or 'value'")
    end
    local function register_submenu(submenu_title, url)
        local function generated_callback(...)
            local fields = {...};
            open_url_with_field(url, fieldname, fieldtype, fields)
        end
        register_packet_menu(menu_title .. "/" .. submenu_title, generated_callback, fieldname);
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
-- IP Address Analysis
-------------------------------------------------

-- Register a callback for both Source and Dest IPs
local function register_both_src_dest_IP(menu_title, url)

    local function generated_callback_src(...)
        local fields = {...};
        local fieldname = "ip.src"
        local fieldtype = "display"
        return open_url_with_field(url, fieldname, fieldtype, fields)
    end
    local function generated_callback_dest(...)
        local fields = {...};
        local fieldname = "ip.dst"
        local fieldtype = "display"
        return open_url_with_field(url, fieldname, fieldtype, fields)
    end


    register_packet_menu("IP Dest/" .. menu_title, generated_callback_dest, "ip.dst");
    register_packet_menu("IP Src/" .. menu_title, generated_callback_src, "ip.src");

end

local function register_both_src_dest_IPv6(menu_title, url)
    local function generated_callback_v6_src(...)
        local fields = {...};
        local fieldname = "ipv6.src"
        local fieldtype = "display"
        return open_url_with_field(url, fieldname, fieldtype, fields)
    end
    local function generated_callback_v6_dst(...)
        local fields = {...};
        local fieldname = "ipv6.dst"
        local fieldtype = "display"
        return open_url_with_field(url, fieldname, fieldtype, fields)
    end
    register_packet_menu("IP Dest/" .. menu_title, generated_callback_v6_dst, "ipv6.dst");
    register_packet_menu("IP Src/" .. menu_title, generated_callback_v6_src, "ipv6.src");
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
register_dns_query_name("URLScan for queried host", "https://urlscan.io/api/v1/search/?q=domain:")

-- HTTP Host
register_http_host = create_registration_url_with_field("HTTP Host", "http.host", "value")
register_http_host("Alienvault OTX", "https://otx.alienvault.com/indicator/domain/")
register_http_host("Google", "https://www.google.com/search?q=")
register_http_host("URLScan", "https://urlscan.io/api/v1/search/?q=domain:")

register_http_host_cmd = create_registration_command_with_field("HTTP Host", "http.host", "value")
register_http_host_cmd("nslookup", "nslookup")

if determine_os == "win" then
    register_http_host_cmd("ping", "ping")
elseif determine_os() == "nix" then
    register_http_host_cmd("ping", "ping -c 4 ")
end

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


-- IMF (SMTP)
register_packet_menu("IMF/Spamhaus for email sender", lookup_spamhaus_imf_from, "imf.from");
if SPLUNK_URL ~= nil then
    register_packet_menu("IMF/Splunk search for subject", search_field_value_in_splunk("imf.subject"), "imf.subject");
end

-- IPv4
register_both_src_dest_IP("ASN lookup", "https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=asn%3a")
register_both_src_dest_IP("IP Abuse DB lookup", "https://www.abuseipdb.com/check/")
register_both_src_dest_IP("IP Location lookup", "https://www.iplocation.net/ip-lookup?submit=IP+Lookup&query=")
register_both_src_dest_IP("IP Void scan", "https://www.ipvoid.com/scan/")
register_both_src_dest_IP("Shodan search", "https://www.shodan.io/host/")
register_both_src_dest_IP("VirusTotal IP Lookup", "https://www.virustotal.com/gui/ip-address/")

-- IPv6
register_both_src_dest_IPv6("ASN lookup", "https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=asn%3a")
register_both_src_dest_IPv6("IP Abuse DB lookup", "https://www.abuseipdb.com/check/")
register_both_src_dest_IPv6("IP Location lookup", "https://www.iplocation.net/ip-lookup?submit=IP+Lookup&query=")
register_both_src_dest_IPv6("Shodan search", "https://www.shodan.io/host/")
-- TODO: will need to convert the ':' to \%253A
-- register_both_src_dest_IPv6("VirusTotal IP Lookup", "https://www.virustotal.com/gui/ip-address/")

-- Note: This action requires setting the SPLUNK_URL:
if SPLUNK_URL ~= nil then
    register_both_src_dest_IP("Splunk search", SPLUNK_URL)
end

-- TLS
register_tls_ja3_client = create_registration_url_with_field("TLS", "tls.handshake.ja3", "value")
register_tls_ja3_client("JA3/Client Lookup", "https://sslbl.abuse.ch/ja3-fingerprints/")
register_tls_ja3_server = create_registration_url_with_field("TLS", "tls.handshake.ja3s", "value")
register_tls_ja3_server("JA3/Server Lookup", "https://sslbl.abuse.ch/ja3-fingerprints/")

register_tls_sni = create_registration_url_with_field("TLS", "tls.handshake.extensions_server_name", "value")
register_tls_sni("Mozilla Observatory Headers Check", 'https://observatory.mozilla.org/analyze/')
register_tls_sni("URLScan", 'https://urlscan.io/api/v1/search/?q=domain:')
register_tls_sni_cmd = create_registration_command_with_field("TLS", "tls.handshake.extensions_server_name", "value")
register_tls_sni_cmd("nslookup SNI", "nslookup")

if determine_os() == "win" then
    register_tls_sni_cmd("ping SNI", "ping")
elseif determine_os() == "nix" then
        register_tls_sni_cmd("ping SNI", "ping -c 4 ")
end

register_tls_sni("SSL Checker scan", 'https://www.sslshopper.com/ssl-checker.html#hostname=')
register_tls_sni("SSL Labs report", "https://www.ssllabs.com/ssltest/analyze.html?d=")
register_tls_sni("VirusTotal SNI Lookup", 'https://www.virustotal.com/gui/domain/')
