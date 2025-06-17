from coordinator import Coordinator
from pyvirtualdisplay import Display
from conf import Conf
import utils
import asyncio
import time

async def main() -> None:
    config = Conf()
    logger = utils.setup_logger(config.FILE_PATHS["log_file_path"])
    coord = Coordinator(config)
    await coord.run()


if __name__ == "__main__":
    start = time.time()
    with Display(visible=False) as _:
        asyncio.run(main())
    end = time.time()

    print("\nExecution time is :",
      (end-start), "secs")
    print("Disclaimer: The final statistics output might not be accurate due to frequency of update")
