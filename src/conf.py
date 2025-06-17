class Conf:

    NR_OF_WORKERS = 4

    #specify megabytes, the product will change it to bytes.
    KEYLOG_FILE_SIZE_LIMIT = 500 * (1024 * 1024)

    #in seconds
    SSLKEY_FILE_CHECK_INTERVAL = 3600

    HE_CH_LIST = [
    "Sec-CH-UA-Arch",
    "Sec-CH-UA-Bitness",
    "Sec-CH-UA-Form-Factor",
    "Sec-CH-UA-Full-Version",
    "Sec-CH-UA-Full-Version-List", #deprecated
    "Sec-CH-UA-Model",
    "Sec-CH-UA-Platform-Version",
    "Sec-CH-UA-WoW64",
    "Sec-CH-Prefers-Color-Scheme",
    "Sec-CH-Prefers-Reduced-Motion",
    "Sec-CH-Prefers-Reduced-Transparency",
    "Content-DPR", #deprecated
    "Device-Memory", #deprecated
    "DPR", #deprecated
    "Viewport-Width", #deprecated
    "Width", #deprecated
    "Downlink",
    "ECT",
    "RTT"
    ]
    #webpage timer is seconds
    #capture duration is seconds
    NETWORK_AND_CAPTURE_CONFIG = {
        "interface": "wlp2s0",
        "capture_duration": 100,
        "webpage_timer": 9,
        "capture_filter": "tcp port 443 or udp port 443",
        "display_filter": "((tls.handshake.extension.type == 17513 || tls.handshake.extension.type == 17613) && "
            "!(tls.handshake.type == 1) && "
            "(ip.src != 1.1.1.1)) || "
            "(http2.type == 137) || "
            "(http3.frame_type == 137)",
        "playwright_device": "Desktop Chrome"
    }

    FILE_PATHS = {
        "log_file_path": "crawler_logs.log",
        "database_path": "ch_db.db",
        "trancolist_path": "100k_tranco.csv",
        "pcap_dump_path": "network_captures/",
        "hexdump_dump_path": "sample_hexdumps/",
        "sslkeylogs_path": "sslkeys.log",
        "cookie_dialouge_path": "cookie_dialouges.txt"
    }

