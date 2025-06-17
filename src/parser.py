import re
import logging
from math import ceil
from typing import List
logger = logging.getLogger("parser")

"""
Parsing functions for a given hexdump 

Helpers: pre_parse_hexdump, detect_HE_CH, parse_decrypted_sections

main parser: parse_hexdump_for_CH_requests

only the main parser should be called from outside the file.
"""



#local debugging purposes
he_ch_list_local = [
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


def pre_parse_hexdump(file_path: str) -> List[tuple[str, str]]:
    """
    Pre-parse a hexdump file to extract only the relevant sections.
    relevant parts include Decrpyed QUIC and TLS dumps. 

    Args:
        file_path (str): Path to the hexdump file.

    Returns:
        List[Tuple[str, str]]: A list of tuples containing:
            - The protocol type:
                "ALPS": For TLS handshake with ALPS (over TCP/QUIC for HTTP3).
                "ACCEPT_CH": For a routine HTTP2 ACCEPT_CH frame during connection.
                "QUIC, as it is not easy to differentiate if it is a http3 ACCEPT_CH frame or TLS handshake ALPS usage when QUIC is used."
            Disclaimer, this protocol identification is best effort, and different parts of the code might change the protocol identified here.

            - The decrypted TLS/QUIC section content. Still in hexdump format
    """

    #regex setup for the headers in the hexdump
    misc_header_start = re.compile(r"""
        ^ 
        (?!Decrypted\ TLS|Decrypted\ QUIC)  # Exclude these two headers
        (.+?)  # First capturing group: match any header name up to the space
        \s  # A single space
        \(
        (\d+)  # Second capturing group: one or more digits
        \sbytes\)  # Literal text " bytes)"
    """, re.VERBOSE)

    Reassembled_tcp_start = re.compile(r'^(Reassembled TCP) \((\d+) bytes\)')
    Decrypted_tls_start = re.compile(r'^(Decrypted TLS) \((\d+) bytes\)')
    Decrypted_quic_start = re.compile(r'^(Decrypted QUIC) \((\d+) bytes\)')

    
    previous_header: str = ""
    decrypted_tls_sections: List[tuple[str, str]] = []

    with open(file_path, 'r') as file:
        lines = list(file)  # Read all lines for index-based processing
        i = 0

        while i < len(lines):
            line = lines[i].rstrip()

            # Match frame or TCP start
            frame_match = misc_header_start.match(line)
            if frame_match:
                nr_bytes = int(frame_match.group(2))
                skip_lines = ceil(nr_bytes / 16) + 1
                # Determine if this is a TCP reassembly
                previous_header = "Reassembled tcp" if Reassembled_tcp_start.match(line) else "other"
                i += skip_lines
                continue

            # Match decrypted TLS start
            decrypted_tls_match = Decrypted_tls_start.match(line)
            if decrypted_tls_match:
                nr_bytes = int(decrypted_tls_match.group(2))
                skip_lines = ceil(nr_bytes / 16)

                # Parse the next `skip_lines` immediately
                section_lines = []
                for _ in range(skip_lines):
                    i += 1
                    if i < len(lines):
                        section_lines.append(lines[i].rstrip())

                # Determine protocol type
                curr_protocol = "ALPS" if previous_header == "Reassembled tcp" else "ACCEPT_CH"
                decrypted_tls_sections.append((curr_protocol, "\n".join(section_lines)))

                previous_header = "decrypted tls"
                #skip one more to exactly land on the next header
                i += 1
                continue

            # Match reassembled handshake start
            decrpyted_quic_match = Decrypted_quic_start.match(line)
            if decrpyted_quic_match:
                nr_bytes = int(decrpyted_quic_match.group(2))  # Extract byte count
                skip_lines = ceil(nr_bytes / 16)

                # Parse the next `skip_lines` immediately
                section_lines = []
                for _ in range(skip_lines):
                    i += 1
                    if i < len(lines):
                        section_lines.append(lines[i].rstrip())

                decrypted_tls_sections.append(("QUIC", "\n".join(section_lines)))

                previous_header = "quic"
                #skip one more to exactly land on the next header
                i += 1
                continue

            #if we reach here, none of the previous headers match, so we dont know what to do
            #skip one line for now
            i+=1

    return decrypted_tls_sections



def detect_HE_CH(parsed_str: str, he_ch_headers: List[str]) -> tuple[str, List[str]]:
    """
    Parse a given string to detect if high-entropy client hints (HE CH) were requested.

    Args: 
        parsed_str (str): The string of ASCII information to process.
        he_ch_headers (List[str]): A list of high-entropy client hint headers to scan for.

    Returns:
        Tuple[str, List[str]]: A tuple containing:
            - The website for which client hints were requested.
            - The list of specific high-entropy CH headers that were requested.
        If not found, return an empty tuple.
    """
    # Detect the website for HTTPS with a valid domain
    website_match = re.search(r"https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", parsed_str)
    website = website_match.group(0) if website_match else None

    # Detect high-entropy client hints
    he_ch_list = [header for header in he_ch_headers if header in parsed_str]

    if website and he_ch_list:
        return website, he_ch_list
    return ()

def check_alps_protocol(parsed_str: str, domain_match: re.Match) -> bool:
    domain_start = domain_match.start()
    codepoint_str: str = parsed_str[domain_start - 15:domain_start - 13]
    #"Di" is the ascii of the codepoint 17513 and "D " is the ascii of the codepoint 17613. "D " because the second character is not ascii, and the parser turns those into spaces.
    if domain_start >= 15 and (codepoint_str == "Di" or codepoint_str == "D "):
        return True
    return False


def parse_decrypted_sections(decrypted_sections: List[tuple[str, str]], he_ch_list: List[str], buffer_size: int = 320) -> List[tuple[str, str, List[str]]]:
    """
    Parse hexdump of network capture to extract high entropy client hints

    Args:
        decrypted sections: the sections of data from the hexdump we are interested in
        he_ch_list (List[str]): the list of high entropy client hint requests to be searched for in the hexdump
        buffer_size (int): Number of bytes to process in each chunk. 
            A larger number will degrade performance, but also decrease the chance we fragment a ch request, causing us to not detect it.
            Multiples of 60 create best results

    Returns:
        List[Tuple [str, str, List[str]]]: A list of tuples containing:
            - The website for which client hints were requested.
            - The 'protocol' that this decrypted section is a part of, either ALPS or ACCEPT_CH
            - The list of specific high entropy CH that were requested.
    """

    result_tuples: List[tuple[str, str, List[str]]] = []
    domain_pattern = re.compile(r'https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    for protocol, section in decrypted_sections:
        buffer = bytearray()

        for line in section.splitlines():
            # Extract the hex bytes (ignoring the first 2 octets)
            hex_data = re.findall(r'[0-9a-fA-F]{2}', line)[2:]
            buffer.extend(int(byte, 16) for byte in hex_data)

            # Process the buffer in chunks of buffer_size
            while len(buffer) >= buffer_size:
                chunk = buffer[:buffer_size]
                buffer = buffer[buffer_size:]
                parsed_str = ''.join(chr(b) if 32 <= b <= 126 else ' ' for b in chunk)

                match = domain_pattern.search(parsed_str)
                if match and check_alps_protocol(parsed_str, match):
                    protocol = "ALPS"

                #send the chunk for CH detection
                result: tuple[str, List[str]] = detect_HE_CH(parsed_str, he_ch_list)
                if result:
                    website, CH_list = result
                    result_tuples.append((website, protocol, CH_list))
                    #move onto the next section because we already found CH info
                    break

        # Process remaining data in the buffer
        if buffer:
            parsed_str = ''.join(chr(b) if 32 <= b <= 126 else ' ' for b in buffer)
            match = domain_pattern.search(parsed_str)
            if match and check_alps_protocol(parsed_str, match):
                protocol = "ALPS"

            result = detect_HE_CH(parsed_str, he_ch_list)
            if result:
                website, CH_list = result
                result_tuples.append((website, protocol, CH_list))

    return result_tuples

def parse_hexdump_for_CH_requests(file_path: str, he_ch_list: List[str], buffer_size: int = 320) -> List[tuple[str, str, List[str]]]: 
    """top-level parser for finding if a given hexdump from tshark has High entropy CH requests.
    Args:
        file_path (str): the file path to the hexdump
        he_ch_list (List[str]): A list of high entropy client hints to look for in the hexdump
        buffersize (int): The buffer chunks in which the hexdump will be parsed. The bigger the less chances of us missing information due to fragmentation,
            but also less performant we will be. 

    Returns:
        A list of tuples containing:
            - the website to which CH were requested to
            - the protocol which was used to request CH
            - the list of client hints that were requested
    """

    decrypted_sections: List[tuple[str, str]] = pre_parse_hexdump(file_path)

    return parse_decrypted_sections(decrypted_sections, he_ch_list, buffer_size)


if __name__ == "__main__":
    print(parse_hexdump_for_CH_requests("sample_hexdumps/alps_test.txt", he_ch_list_local))
