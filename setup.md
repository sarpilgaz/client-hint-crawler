This file details the setup process for the crawler.

# System dependencies
The crawler requires the following system dependencies on a Linux system:
- Python 3.12 or higher
- xvfb
- sqlite3
- tshark
example on debian-based systems:
```bash
sudo apt install python xvfb sqlite3 tshark
```

Every instance of shell started needs to have the environment variable SSLKEYLOGFILE set to the location of the keylog file:
```bash
export SSLKEYLOGFILE=/path/to/sslkeylogfile.txt
```
This needs to be set in the .rc file of the shell used on the system.

# Python setup
Create a virtual environment and install the required packages:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Playwright setup
Chromium needs to be downloaded to run the crawler as is:
```bash
playwright install-deps chromium && playwright install chromium
```

# Tshark setup
The path to the sslkeylog file needs to be set in the wireshark configuration. This can be done via the wireshark GUI, which should also make it work with tshark, or by editing the configuration file directly:
Probably in ``` $HOME/.config/wireshark/preferences```
```bash
tls.keylog_file: /path/to/sslkeylogfile.txt
```

# Folder and config setup
The following folders and files need to be created in the root of the repository:

- A folder to keep the network captures generated during the crawl 
- A folder to keep the hexdumps generated during the crawl 
- A file for the database
Example:
```bash
mkdir network_captures
mkdir sample_hexdumps
touch crawler_logs.txt #optional, should be auto-created
touch sslkeys.log #optional, should be auto-created
touch ch_db.db
```
Edit the ```conf.py``` file, the FILE_PATHS dict at the end, to set the paths to the folders and files created above. The default paths should work if the folders and files are created in the root of the project as given in the example.

# Database setup
The database needs to be set up with the required schemas. This can be done using the sqlite3 CLI:

Example:
```bash
sqlite3 ch_db.db
```
Then, run the following commands to create the necessary tables:
```sql 
CREATE TABLE client_hints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website_id INTEGER NOT NULL,
        hint_name TEXT NOT NULL,
        FOREIGN KEY (website_id) REFERENCES websites (id) ON DELETE CASCADE,
        UNIQUE (website_id, hint_name)
);

CREATE TABLE websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT UNIQUE NOT NULL,
        request_origin TEXT NOT NULL
);

CREATE TABLE client_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visited_domain TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    UNIQUE (visited_domain, target_domain)
);


CREATE TABLE client_hints_client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    hint_name TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES client_requests (id) ON DELETE CASCADE,
    UNIQUE (request_id, hint_name)
);
```
Created schemas can then be checked:
```bash
.tables
.schema
```

# Additional config setup
The trancolist file, or the list of websites to be crawled, should be in the root of the repo as it is, and the name should be set in the ```conf.py```
Note that any custom list should be in the exact format as the tranco list provided. 

That is: <line_number>,<domain_to_visit>\n

The network config part of ```conf.py``` has a field named "display_filter", which has a ip address as source to be filtered. This should be set to the ip address of the network interface used for the crawl. This can be found using:
```bash
ip addr
```
Similarly, the field "interface" should be set to the network interface used for the crawl, which can also be found using the same command.

Even if the source IP is incorrectly set, the crawler should still run fine, but performance will degrade because certain redundant packets will also be analyzed.

The ```conf.py``` file has additional config options at the top, such as number of parallel crawlers to run, how big a sslkeylog file should be before it is rotated, intervals to check the sslkeylog file size, and the list of Client Hints to be checked for in ALPS.

# Running the crawler 
To run the crawler, ensure the virtual environment is activated and then execute the `crawler.py` script from the root of the project:
```bash
source venv/bin/activate 
python src/crawler.py
```
