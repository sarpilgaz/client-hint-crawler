import asyncio
import logging

class TrancoLoader:
    """Class: tranco_loader
    Tasked with loading and formatting urls to be processed by workers

    Fields:
        logger: the logger
        tranco_file: the path to the tranco list to be loaded from. The format must conform to the .csv given by the trancolist download.
    """
    def __init__(self, tranco_file: str):
        self.logger = logging.getLogger("Tranco Loader")
        self.tranco_file = tranco_file

    async def load_urls_from_tranco(self, queue: asyncio.Queue) -> None:
        """function to format and load the urls from the given trancolist file into the work queue given"""
        with open(self.tranco_file, "r") as f:
            for line in f:
                url = line.split(",")[1]
                url = "https://"+url
                await queue.put(url)
        self.logger.info("All URLs from the Tranco list has been loaded")
        