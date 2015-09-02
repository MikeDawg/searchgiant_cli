__author__ = 'alexander'
import os
import logging
from logging import FileHandler
from config import ConfigLoader
from oi.IO import IO
import time
import shutil
from onlinestorage import OnlineStorage
from googledrive import GoogleDrive


class DefaultConfigs:
    defaults = {"google_drive":
                    ("TOKEN_ENDPOINT = 'https://accounts.google.com/o/oauth2/token'\r\n"
                     "OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'\r\n"
                     "OAUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/auth'\r\n"
                     "API_VERSION = 'v2'\r\n"
                     "API_ENDPOINT = 'https://www.googleapis.com/drive/v2'\r\n"
                     "REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'\r\n"
                     "CLIENT_ID = ''\r\n"
                     "CLIENT_SECRET = ''\r\n")
                }


class Project:
    shutdown_signal = 0
    pause_signal = 0

    working_dir = ""
    data_dir = ""
    log_dir = ""
    transaction_log = ""
    exception_log = ""
    metadata_file= ""
    config = None
    transaction_logger = None
    exception_logger = None
    name = ""
    threads = 5
    args = None

    def __init__(self, args):
        # Meh...
        working_dir = args.project_dir
        project_name = args.service
        threads = args.threads
        # /Meh...

        self.args = args
        self.name = project_name
        self.threads = threads
        self.working_dir = os.path.join(working_dir, self.name)

        self.data_dir = os.path.join(self.working_dir, "data")
        self.log_dir = os.path.join(self.working_dir, "logs")
        self.config_file = os.path.join(self.working_dir, "config.cfg")
        if os.path.exists(self.working_dir):
            IO.put("Resuming project in " + self.working_dir, "highlight")
        else:
            IO.put("Initializing project in " + self.working_dir, "highlight")

        IO.put("Data path is " + self.data_dir)
        IO.put("Log path is " + self.log_dir)
        IO.put("Config file is " + self.config_file)

        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir, exist_ok=True)
            IO.put("Working directory not found, creating from scratch", "warn")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir, exist_ok=True)
            IO.put("Data directory not found, creating from scratch", "warn")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir, exist_ok=True)
            IO.put("Logging directory not found, creating from scratch", "warn")

        if not os.path.isfile(self.config_file):
            IO.put("Config file not found, creating default config file", "warn")
            with open(self.config_file, 'w') as f:
                f.write(DefaultConfigs.defaults[self.name])

        self.config = ConfigLoader.ConfigLoader()
        self.config.from_file(self.config_file)

        self.transaction_log = os.path.join(self.log_dir, "transaction.log")
        self.exception_log = os.path.join(self.log_dir, "exception.log")
        self.metadata_file = os.path.join(self.working_dir, "metadata.csv")

        self.transaction_logger = logging.getLogger(project_name + "_t")
        self.exception_logger = logging.getLogger(project_name + "_e")
        self.transaction_logger.setLevel(20)
        self.exception_logger.setLevel(20)
        tfh = FileHandler(self.transaction_log)
        efh = FileHandler(self.exception_log)

        fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        fmt.converter = time.gmtime
        tfh.setFormatter(fmt)
        efh.setFormatter(fmt)

        self.transaction_logger.addHandler(tfh)
        self.exception_logger.addHandler(efh)

    def start(self):
        instance = OnlineStorage.OnlineStorage
        print(self.args.mode)
        print(self.args.service)
        if self.args.service == "google_drive":
            instance = GoogleDrive.GoogleDrive(self)

        if self.args.mode == "full":
            instance.full_sync()

        if self.args.mode == "metadata":
            instance.metadata()

    def log(self, type, message, level, stdout=False):

        levels = {}
        levels['info'] = 20
        levels['warning'] = 30
        levels['error'] = 40
        levels['critical'] = 50
        levels['highlight'] = 20

        if stdout:
            IO.put(message, level)

        if type.lower() == "exception":
            self.exception_logger.log(levels[level], message)

        self.transaction_logger.log(levels[level], message)

    def save(self, key, value):
        self.config.from_file(self.config_file)
        self.config[key] = value
        with open(self.config_file,'w') as f:
            for k,v in self.config.items():
                if type(v) is str:
                    f.write('{}="{}"\n'.format(k.upper(),v))
                else:
                    f.write('{}={}\n'.format(k.upper(),v))
        self.config.from_file(self.config_file)

    def savedata(self, data, filepath):
        with open(filepath, 'wb') as f:
            shutil.copyfileobj(data, f)

