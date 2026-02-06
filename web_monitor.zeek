##! Web Traffic Monitor - Zeek Policy Script
##! Production-ready monitoring for HTTP, HTTPS, and DNS traffic
##! Outputs JSON lines to a single log file with external IPs only

@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/dns

module WebMonitor;

export {
    ## Create custom log stream for unified web traffic
    redef enum Log::ID += { LOG };

    ## Log record with all required fields
    type Info: record {
        ts:           time              &log;
        proto:        string            &log;
        src_ip:       addr              &log;
        dst_port:     port              &log;
        ## HTTP fields (plaintext only)
        method:       string            &log &optional;
        uri:          string            &log &optional;
        host:         string            &log &optional;
        user_agent:   string            &log &optional;
        ## HTTPS fields
        sni:          string            &log &optional;
        tls_version:  string            &log &optional;
        cipher:       string            &log &optional;
        ## DNS fields
        query:        string            &log &optional;
        qtype:        string            &log &optional;
    };

    ## Global filter for internal IPs
    global is_external_ip: function(ip: addr): bool;
}

## Check if IP is external (not RFC1918, localhost, link-local, Docker default)
function is_external_ip(ip: addr): bool
{
    # RFC1918 private ranges
    if ( ip in 10.0.0.0/8 )
        return F;
    if ( ip in 172.16.0.0/12 )
        return F;
    if ( ip in 192.168.0.0/16 )
        return F;
    # Localhost
    if ( ip in 127.0.0.0/8 )
        return F;
    # Link-local
    if ( ip in 169.254.0.0/16 )
        return F;
    # Docker default bridge
    if ( ip in 172.17.0.0/16 )
        return F;
    # IPv6 loopback
    if ( ip == [::1] )
        return F;
    # IPv6 link-local
    if ( ip in [fe80::]/10 )
        return F;
    # IPv6 private (ULA)
    if ( ip in [fc00::]/7 )
        return F;
    
    return T;
}

event zeek_init()
{
    # Create the log stream with JSON output
    Log::create_stream(WebMonitor::LOG, [$columns=Info, $path="web_traffic"]);
}

## HTTP request logging (plaintext traffic on port 80)
event http_request(c: connection, method: string, original_URI: string, 
                   unescaped_URI: string, version: string)
{
    local src = c$id$orig_h;
    
    # Skip internal IPs
    if ( ! is_external_ip(src) )
        return;
    
    local rec: Info = [
        $ts = network_time(),
        $proto = "HTTP",
        $src_ip = src,
        $dst_port = c$id$resp_p,
        $method = method,
        $uri = unescaped_URI
    ];
    
    Log::write(WebMonitor::LOG, rec);
}

## HTTP headers for Host and User-Agent
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    # Only process request headers from external IPs
    if ( ! is_orig )
        return;
    
    local src = c$id$orig_h;
    if ( ! is_external_ip(src) )
        return;
    
    local lname = to_lower(name);
    
    if ( lname == "host" || lname == "user-agent" )
    {
        local rec: Info = [
            $ts = network_time(),
            $proto = "HTTP_HEADER",
            $src_ip = src,
            $dst_port = c$id$resp_p
        ];
        
        if ( lname == "host" )
            rec$host = value;
        else if ( lname == "user-agent" )
            rec$user_agent = value;
        
        Log::write(WebMonitor::LOG, rec);
    }
}

## TLS/SSL connection with SNI, version, cipher
event ssl_established(c: connection)
{
    local src = c$id$orig_h;
    
    # Skip internal IPs
    if ( ! is_external_ip(src) )
        return;
    
    if ( ! c?$ssl )
        return;
    
    local rec: Info = [
        $ts = network_time(),
        $proto = "HTTPS",
        $src_ip = src,
        $dst_port = c$id$resp_p
    ];
    
    if ( c$ssl?$server_name )
        rec$sni = c$ssl$server_name;
    
    if ( c$ssl?$version )
        rec$tls_version = c$ssl$version;
    
    if ( c$ssl?$cipher )
        rec$cipher = c$ssl$cipher;
    
    Log::write(WebMonitor::LOG, rec);
}

## DNS query logging
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local src = c$id$orig_h;
    
    # Skip internal IPs
    if ( ! is_external_ip(src) )
        return;
    
    local rec: Info = [
        $ts = network_time(),
        $proto = "DNS",
        $src_ip = src,
        $dst_port = c$id$resp_p,
        $query = query,
        $qtype = DNS::query_types[qtype] ? DNS::query_types[qtype] : fmt("%d", qtype)
    ];
    
    Log::write(WebMonitor::LOG, rec);
}
