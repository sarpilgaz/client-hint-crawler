import sys
from typing import List
from db_interface import Db_interface
from worker import Worker
from tranco_loader import TrancoLoader
from os import stat, path

import asyncio
import aiofiles
import logging
import aioshutil


logger = logging.getLogger("Coordinator")
class Coordinator:
    def __init__(self, config):
        self.config = config
        self.work_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        self.db = Db_interface(self.config.FILE_PATHS["database_path"])
        self.url_loader = TrancoLoader(self.config.FILE_PATHS["trancolist_path"])
        self.sslkey_file_check_period = self.config.SSLKEY_FILE_CHECK_INTERVAL
        self.workers: List[Worker] = []
        self.sslkeys_file_flag = asyncio.Event()
        self.sslkeys_file_flag.set()
        self.total_website_visit_fails = 0
        self.sslkeys_reset_counter = 0
        self.processed_url_counter = 0

        dialouge_list = self.read_cookie_file_into_list()

        for id in range(0, self.config.NR_OF_WORKERS):
            self.workers.append(
                Worker(id, self.work_queue, self.result_queue, 
                       self.config.FILE_PATHS["pcap_dump_path"], 
                       self.config.FILE_PATHS["hexdump_dump_path"], 
                       dialouge_list,
                       self.config.HE_CH_LIST, self.sslkeys_file_flag,
                       **self.config.NETWORK_AND_CAPTURE_CONFIG)
                       )
    
    def read_cookie_file_into_list(self) -> List[str]:
        cookie_file_path = self.config.FILE_PATHS["cookie_dialouge_path"]
        cookie_file = open(cookie_file_path) 
        data = cookie_file.read()
        list = data.split("\n")
        cookie_file.close()

        return list
    
    async def sslkeylog_checker(self) -> None:
        """coroutine to monitor the size of sslkeylog file size, and cleanup if needed"""
        while True:
            await asyncio.sleep(self.sslkey_file_check_period)
            if not await self.check_sslkeys_file_size():
                logger.info("sslkeylogs file found to be too big, starting cleaning process")
                self.sslkeys_file_flag.clear()

                #after sending the signal, make sure they actually stopped working
                for worker in self.workers:
                    while worker.get_working():
                        await asyncio.sleep(2)

                await self.clean_sslkeys_file()
                logger.info("cleaning complete, resuming work")
                self.sslkeys_file_flag.set()
            


    async def check_sslkeys_file_size(self) -> bool:
        """function to check if the sslkeylog file is within the size limit
        this check assumes Config file setup to be in bytes. 
        Returns:
            bool: True if the file is within size limit, false otherwise
        """

        file_info = stat(self.config.FILE_PATHS["sslkeylogs_path"])
        return file_info.st_size <= self.config.KEYLOG_FILE_SIZE_LIMIT

    
    async def clean_sslkeys_file(self) -> None:
        """Function to remove and recreate the sslkeylogs file"""
        keylog_file = self.config.FILE_PATHS["sslkeylogs_path"]
        if path.exists(keylog_file):
            await aioshutil.copyfile(keylog_file, f"sslkeys_{self.sslkeys_reset_counter}.log")

        #opening the file in write mode will truncate it, effectively cleaning it.
        f = await aiofiles.open(keylog_file, "w")
        await f.close()
        self.sslkeys_reset_counter += 1

    
    async def process_results(self) -> None:
        while True:
            result = await self.result_queue.get()
            try:
                if result == ["sentinel"]:
                    break
                await self.db.insert_website_and_hints(result)
            except Exception as e:
                logger.error(f"Error processing result: {e}")
            finally:
                self.result_queue.task_done()

    async def CLI_feedback(self) -> None:
        """Function to report how many websites were processed using the proccessed_url_counter in each worker
        """
        while True:
            await asyncio.sleep(10)
            self.processed_url_counter = sum(worker.processed_url_counter for worker in self.workers)
            self.total_website_visit_fails = sum(worker.failed_visit_count for worker in self.workers)
            success_count = self.processed_url_counter - self.total_website_visit_fails
            
            sys.stdout.write(
            f"\rTotal processed URLs: {self.processed_url_counter} | "
            f"Total failed visits: {self.total_website_visit_fails} | "
            f"Total successful visits: {success_count}  "
            )
            sys.stdout.flush()

    async def run(self) -> None:
        await self.db.connect_to_db()

        # Create tasks
        loader_task = asyncio.create_task(self.url_loader.load_urls_from_tranco(self.work_queue))
        worker_tasks = [asyncio.create_task(self._safe_worker_run(worker)) for worker in self.workers]
        result_task = asyncio.create_task(self.process_results())
        sslkeys_monitor_task = asyncio.create_task(self.sslkeylog_checker())
        cli_feedback_task = asyncio.create_task(self.CLI_feedback())

        try:
            await loader_task
            await self.work_queue.join()

            # Add sentinel to result_queue to stop process_results
            await self.result_queue.put(["sentinel"])
            await self.result_queue.join()

            # Wait for result processing task to finish
            await result_task
        except asyncio.CancelledError:
            logger.warning("Coordinator.run was cancelled.")
        finally:
            # Cleanup worker tasks
            for worker_task in worker_tasks:
                worker_task.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)

            total_failures = sum(worker.failed_visit_count for worker in self.workers)  

            logger.info(f"Total failed website visits: {total_failures}")
            
            sslkeys_monitor_task.cancel()
            await asyncio.gather(sslkeys_monitor_task, return_exceptions=True)

            await asyncio.gather(result_task, return_exceptions=True)

            cli_feedback_task.cancel()
            await asyncio.gather(cli_feedback_task, return_exceptions=True)

            # Close DB connection
            await self.db.close_db()

    async def _safe_worker_run(self, worker) -> None:
        # Extra safety wrapper to catch exceptions in worker.run
        try:
            await worker.run()
        except Exception as e:
            logger.error(f"Worker {worker.id} encountered an error: {e}")
