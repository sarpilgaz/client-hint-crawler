from typing import List
import aiosqlite
import os
import logging
from data_type import DATA_TYPE

logger = logging.getLogger("database")
class Db_interface:
    def __init__(self, db_path: str):
        """Class: Db_interface
        Class to make async sqlite operations

        Fields:
            db_location: the path to the database file to connect to.
            conn: The connection object to the database
            cursor: the cursor object for the database

        Raises: Execption when the path does not have a file.
        """

        self.db_location = db_path
        if not os.path.exists(self.db_location):
            logger.critical("database not found, aborting")
            raise Exception("Database file does not exist. Aborting.")

        self.conn = None
        self.cursor = None

    async def connect_to_db(self) -> bool:   
        """Attempt a db connection to the database located at self.db_location

            Returns: true if success, false otherwise
        """   
        try:
            self.conn = await aiosqlite.connect(self.db_location)
            self.cursor = await self.conn.cursor()
            return True
        except aiosqlite.Error as e:
            logger.error("couldnt connect to db. aborting now.")
            return False

    async def close_db(self) -> None:
        """Close the database connection"""
        await self.conn.close()

    async def insert_server_side_data(self, data: List[tuple[str, str, List[str]]]) -> None:
        for data_chunk in data:
            if not data_chunk:
                #empty tuple, wtf do we do??
                continue
            website, origin, hints = data_chunk
            try:
                #Insert
                await self.cursor.execute(
                "INSERT OR IGNORE INTO websites (website, request_origin) VALUES (?, ?)",
                (website, origin)
                ) 

                res = await self.cursor.execute(
                "SELECT id FROM websites WHERE website = ?",
                (website,)
                )
                row = await res.fetchone()
                if row:
                    website_id = row[0]

                for hint in hints:
                    await self.cursor.execute(
                        "INSERT OR IGNORE INTO client_hints (website_id, hint_name) VALUES (?, ?)",
                        (website_id, hint)
                    )
                await self.conn.commit()

            except aiosqlite.Error as e:
                logger.error(f"database insertion error: {e}\n Data received but not written: {data}")

    async def insert_client_side_data(self, data: List[tuple[str, str, List[str]]]):
        """
        Insert client-side data into the database.

        Each data tuple is:
            (visited_domain, target_domain, [sent_client_hints])
        """
        for data_chunk in data:
            if not data_chunk:
                # Empty tuple, skip it
                continue
            visited_domain, target_domain, hints = data_chunk
            try:
                # Insert or ignore the client request (visited & target pair)
                await self.cursor.execute(
                    "INSERT OR IGNORE INTO client_requests (visited_domain, target_domain) VALUES (?, ?)",
                    (visited_domain, target_domain)
                )

                # Retrieve the id for the inserted (or existing) request
                res = await self.cursor.execute(
                    "SELECT id FROM client_requests WHERE visited_domain = ? AND target_domain = ?",
                    (visited_domain, target_domain)
                )
                row = await res.fetchone()
                if row:
                    request_id = row[0]
                else:
                    logger.error(f"Failed to retrieve client_requests id for ({visited_domain}, {target_domain}).")
                    continue

                # Insert each client-side hint
                for hint in hints:
                    await self.cursor.execute(
                        "INSERT OR IGNORE INTO client_hints_client (request_id, hint_name) VALUES (?, ?)",
                        (request_id, hint)
                    )
                await self.conn.commit()

            except aiosqlite.Error as e:
                logger.error(f"Database insertion error: {e}\nData received but not written: {data_chunk}")

    async def insert_website_and_hints(self, data: tuple[DATA_TYPE, List[tuple[str, str, List[str]]]]) -> None:
        """Insert the given data to the database
        
        Args:
            data: a list of tuples in the format tuple(str, str, list[str]).
            a single tuple in this list represents the following:
                website, origin, [he_client_hints_requested]
        """
        type, data_content = data
        if type == DATA_TYPE.SERVER_SIDE:
            await self.insert_server_side_data(data_content)
        elif type == DATA_TYPE.CLIENT_SIDE:
            await self.insert_client_side_data(data_content)
        else: 
            #should never ever happen, but I believe in Murphy's law
            logger.error(f"database received data of unknown type, the lost data: {data_content}")
            pass
