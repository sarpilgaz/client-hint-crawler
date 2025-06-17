import subprocess
from typing import List
import logging
import asyncio
import re
import aioshutil
import os
import tldextract

from urllib.parse import urlparse
from playwright.async_api import async_playwright
from playwright.async_api import Error, TimeoutError
from parser import parse_hexdump_for_CH_requests
from data_type import DATA_TYPE

logger = logging.getLogger("worker")

class Worker:
    def __init__(self, worker_id: int, work_queue: asyncio.Queue, result_queue: asyncio.Queue, 
                 pcap_loc: str, hexdump_loc: str, cookie_dialouge_list: List[str], he_ch_list: List[str], sslkeys_flag: asyncio.Event,
                 interface: str, capture_duration: int,  webpage_timer: int,
                 capture_filter: str, display_filter: str, playwright_device: str,):
        """
        Class: Worker
        Tasked with doing one unit of work until the programs end
        The unit of work flow is as follows:
            start capture with tshark ->
            visit website ->
            once website vist ends and returns success, filter with tshark ->
            parse results, give results in a format that is writeable to the database. 

            Exact format can be found in parser.parse_decrypted_sections()

        Fields:
            worker_id: a unique integer assigned at creation to identify this worker and its temp files.
            pcap_loc: the location to dump the pcap from capture
            hexdump_loc: the location to dump the hex from display filtering
            interface: the interface to capture on
            capture_duration: the duration to capture for in seconds
            webpage_timer: Time to wait on a visited website to collect network traffic
            capture_filter: the filter to be applied during tshark network capture
            display_filter: the filter to be applied on a given pcap file
            playwright_device: The device for playwright to emulate when crawling, refer to the documentation for exact types
            he_ch_list: the list of high entropy client hints to search for
        """
        self.id = worker_id

        self.sslkeys_flag = sslkeys_flag
        self.working = True
        self.failed_visit_count = 0

        self.pcap_loc = pcap_loc + "worker_" + str(self.id) + "_cap.pcap"
        self.backup_pcap_loc = pcap_loc + "backup_pcaps/"
        self.hexdump_loc = hexdump_loc + "worker_" + str(self.id) + "_hexdump.txt"
        self.interface = interface
        self.capture_duration = capture_duration
        self.webpage_timer = webpage_timer
        self.capture_filter = capture_filter
        self.display_filter = display_filter
        self.playwright_device = playwright_device
        self.he_ch_list = he_ch_list
        self.cookie_dialouges = set(cookie_dialouge_list)

        self.work_queue: asyncio.Queue = work_queue
        self.result_queue: asyncio.Queue = result_queue

        self.cookie_regex = self.setup_cookie_regex()

        self.processed_url_counter = 0

        self.he_ch_set = set(ch.lower() for ch in self.he_ch_list)

    def get_working(self) -> bool:
        return self.working
    
    def setup_cookie_regex(self):
        escaped_lines = [re.escape(line.strip()) for line in self.cookie_dialouges if line.strip()]
        
        combined_pattern = r'^\s*(' + '|'.join(escaped_lines) + r')\s*$'
        return re.compile(combined_pattern, re.IGNORECASE)
    
    def get_main_domain(self, url: str) -> str:
        parsed_url = urlparse(url)
        extracted = tldextract.extract(parsed_url.netloc)
        return ".".join(part for part in [extracted.subdomain, extracted.domain, extracted.suffix] if part)

    async def start_capture(self, stop_flag: asyncio.Event) -> int:
        """Start the tshark network capture asynchronously.
        
        Returns: the exit code of the tshark command.        
        """
        stop_condition = "duration:" + str(self.capture_duration)

        try:
            process = await asyncio.create_subprocess_exec(
                    "tshark",
                    "-i", self.interface,
                    "-f", self.capture_filter,
                    "-w", self.pcap_loc,
                    "--autostop", stop_condition,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

            await stop_flag.wait()

            try:
                process.terminate()
            except ProcessLookupError:
                logger.info(f"tshark process in worker {self.id} has ended prematurely, probably timeout.")
                return process.returncode
            await process.wait()

            return process.returncode

        except FileNotFoundError:
            logger.error("tshark is not installed or not in the PATH. how the fuck did we even get here?")
            return -1

    async def filter_and_hexdump(self) -> int:
        """function to display filter the pcap file and create a hexdump at hexdump_loc

        Returns: return code of the tshark command

        """
        display_filter = self.display_filter

        try:
            with open(self.hexdump_loc, "w") as hexdump_file:
                ret = subprocess.run(
                    [
                        "tshark",
                        "-r", self.pcap_loc,
                        "-Y", display_filter,
                        "--hexdump", "noascii"
                    ],
                    stdout=hexdump_file,
                    check=True  # Raise an error if the command fails
                )
                return ret.returncode
        except subprocess.CalledProcessError as e:
            logger.error(f"Error while running tshark: {e}")
            return e.returncode
        except FileNotFoundError:
            logger.error("tshark is not installed or not in the PATH. how the fuck did we even get here?")
        except IOError as e:
            logger.error(f"Error writing to hexdump file: {e}")
    
                
    async def search_iframe_for_cookie_dialogue(self, page):
        """Search iframes for cookie dialog buttons
        """
        frames = await page.locator("iframe").all()

        for frame in frames:
            elements = await frame.content_frame.get_by_text(self.cookie_regex)
            for elem in elements:
                try:
                    await elem.click(timeout=1000)
                    return 0
                except (Error, TimeoutError) as e:
                    pass
        return -1
    
    async def click_for_real(self, page):
        """Use the cookie regex to find all candidates for a cookie dialogue 
        currently exists on first successful click.
        """
        
        elements = await page.get_by_text(self.cookie_regex).all()
    
        for elem in elements:
            try:
                await elem.click(timeout=1000)
                return 0
            except (Error, TimeoutError) as e:
                pass

        return -1
    
    def extract_ch_header_ips(self, pcap_path):
        """
        Extracts source IP addresses from a pcap file where the 'accept-ch' HTTP/2 header is present.
        Args:
            pcap_path (str): The path to the pcap file.
        Returns:
            list: A list of source IP addresses as strings.
        """
        try:
            command = [
                'tshark',
                '-r', pcap_path,
                '-Y', 'http2.header.name == "accept-ch" || http3.header.header.name == "accept-ch" || http2.header.name == "critical-ch" || http3.header.header.name == "critical-ch"',
                '-T', 'fields',
                '-e', 'ip.src'
            ]

            result = subprocess.run(command, capture_output=True, text=True, check=True)

            # Split the output into lines and filter out any empty strings
            ip_addresses = [line for line in result.stdout.splitlines() if line]

            return ip_addresses

        except subprocess.CalledProcessError as e:
            logger.error(f"An error occurred while running tshark: {e}")
            return []
    
    async def visit_webpage(self, url: str, browser, desktop):
        """
        Visit the given URL using a fresh browser, context, and page.
        Closes all resources at the end.

        Args:
            url: URL to visit.
            playwright: The Playwright instance.
            desktop: Device configuration dictionary.

        Returns:
            A tuple (ret_val, ch_header_info) where ret_val is -1 for errors, 0 otherwise,
            and ch_header_info is a list of tuples with header information.
        """
        ret_val = 0
        ch_header_info = []
        request_info = []
        origin_domain = self.get_main_domain(url)

        async def handle_response(response):
            """Intercept responses to check for 'accept-ch' and 'critical-ch' headers."""
            try:
                server_addr = await response.server_addr()
                if not server_addr:
                    return
                domain = self.get_main_domain(response.url)
                ip = server_addr['ipAddress']

                headers = await response.all_headers()
                accept_ch = headers.get("accept-ch")
                if accept_ch:
                    accept_ch_list = [ch.strip() for ch in accept_ch.split(',')]
                    ch_header_info.append((domain, ip, accept_ch_list))

                critical_ch = headers.get("critical-ch")
                if critical_ch:
                    critical_ch_list = [crit_ch.strip() for crit_ch in critical_ch.split(',')]  
                    ch_header_info.append((domain, ip, critical_ch_list))    
                
            except Exception as e:
                #probably overloaded with reponses, and some of them will not be processed before moving on. Such is life.
                pass
            
        async def handle_request(request):
            try:
                headers = await request.all_headers()
                target_domain = self.get_main_domain(request.url)

                sent_headers = [ch for ch in self.he_ch_set if ch in headers]
                if sent_headers:
                    for i, (_, domain_sent, ch_list) in enumerate(request_info):
                        if target_domain == domain_sent:
                            union_list = list(set(sent_headers).union(ch_list))
                            request_info[i] = (origin_domain, target_domain, union_list)
                            return
                    request_info.append((origin_domain, target_domain, sent_headers))
            except Exception as e:
                #probably overloaded with requests, and some of them will not be processed before moving on. Such is life.
                pass

        context = page = None
        try:
            # Launch a fresh context and page then visit the URL.
            context = await browser.new_context(**desktop)
            page = await context.new_page()
            page.on("response", handle_response)
            page.on("request", handle_request)

            response = await page.goto(url, timeout=17000)
            if response and response.status == 500:
                logger.warning(f"HTTP 500 for {url}.")
                ch_header_info.clear()
                ret_val = -1

            # Wait a short period to let the site load.
            await page.wait_for_timeout(1000)

            if (await self.click_for_real(page)) == -1:
                if (await self.search_iframe_for_cookie_dialogue(page)) == -1:
                    logger.info(f"No cookie dialogue found on or in iframes for: {url}")

            # Additional wait to allow further traffic.
            await page.wait_for_timeout(self.webpage_timer)

        except Exception as e:
            logger.warning(f"Failed to visit {url}: {e}")
            ch_header_info.clear()
            ret_val = -1
        finally:
            # Ensure all resources are closed.
            if page is not None:
                await page.close()
            if context is not None:
                await context.close()
            return ret_val, ch_header_info, request_info
        
    def cross_reference_response_ips(self, header_ch_info, http2_ip_addrs):
        playwright_ips = {ip for _, ip, _ in header_ch_info}

        header_results = []
        for ip in playwright_ips.intersection(http2_ip_addrs):
            for domain, ip_addr, header_value in header_ch_info:
                if ip_addr == ip:
                    header_results.append((domain, "http2/3 header", header_value))

        return header_results

    async def backup_pcap(self, url: str) -> None:
        # save a backup every few URLs of a worker.
        if self.processed_url_counter % 100 != 0:
            return

        main_domain = self.get_main_domain(url)
        backup_file_name = f"{main_domain}.pcap"
        try:
            dst_loc = os.path.join(self.backup_pcap_loc, backup_file_name)
            os.makedirs(self.backup_pcap_loc, exist_ok=True)
            await aioshutil.copyfile(self.pcap_loc, dst_loc)
        except Exception as e:
            logger.error(f"backing up a file failed in worker {self.id}, the domain was: {main_domain}")

    async def run(self) -> None:
        """
        Main worker loop that creates a fresh browser for each URL.
        """
        stop_event = asyncio.Event()
        async with async_playwright() as playwright:
            desktop = playwright.devices[self.playwright_device]
            browser = await playwright.chromium.launch(headless=False, channel="chromium")
            while not self.work_queue.empty():
                if not self.sslkeys_flag.is_set():
                    self.working = False
                    await self.sslkeys_flag.wait()

                url = await self.work_queue.get()
                try:
                    stop_event.clear()
                    capture_task = asyncio.create_task(self.start_capture(stop_event))

                    webpage_ret, header_ch_info, request_ch_info = await self.visit_webpage(url, browser, desktop)

                    # End network capture
                    stop_event.set()
                    capture_ret = await capture_task

                    if webpage_ret == -1 or capture_ret != 0:
                        self.failed_visit_count += 1       
                        continue

                    ret = await self.filter_and_hexdump()
                    if ret != 0:
                        logger.warning(f"display filtering tshark command failure in worker {self.id}")
                        self.failed_visit_count += 1
                        continue

                    result = parse_hexdump_for_CH_requests(self.hexdump_loc, self.he_ch_list, 320)
                    http2_ip_addrs = self.extract_ch_header_ips(self.pcap_loc)
                    header_results = self.cross_reference_response_ips(header_ch_info, http2_ip_addrs)

                    hex_data = (DATA_TYPE.SERVER_SIDE, result)
                    response_header_data = (DATA_TYPE.SERVER_SIDE, header_results)
                    request_header_data = (DATA_TYPE.CLIENT_SIDE, request_ch_info)

                    await self.result_queue.put(hex_data)
                    await self.result_queue.put(response_header_data)
                    await self.result_queue.put(request_header_data)

                    await self.backup_pcap(url)

                except Exception as e:
                    logger.error(f"Error processing URL {url} in worker {self.id}: {e}")
                finally:
                    self.working = True
                    self.processed_url_counter += 1
                    self.work_queue.task_done()
                    
            await browser.close()
