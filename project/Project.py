# searchgiant - Open source remote forensic acquisition tool
# Copyright (C) 2015  Alexander Urcioli <alexurc@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
from dropbox import Dropbox
from gmail import GMail
import http.client


class DefaultConfigs:
    defaults = ("CLIENT_ID = ''\r\nCLIENT_SECRET = ''\r\n")

class Project:
    shutdown_signal = 0
    pause_signal = 0

    working_dir = ""
    transaction_log = ""
    exception_log = ""
    verification_log = ""
    metadata_file = ""
    config = None
    transaction_logger = None
    exception_logger = None
    name = ""
    threads = 5
    args = ""

    project_folders = {}

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
        self.acquisition_dir = os.path.join(self.working_dir, "acquisition")

        if os.path.exists(self.working_dir):
            IO.put("Resuming project in " + self.working_dir, "highlight")
        else:
            os.makedirs(self.working_dir, exist_ok=True)
            IO.put("Initializing project in " + self.working_dir, "highlight")

        self.project_folders["data"] = os.path.join(self.acquisition_dir, "data")
        self.project_folders["logs"] = os.path.join(self.working_dir, "logs")
        self.project_folders["metadata"] = os.path.join(self.acquisition_dir, "metadata")
        self.project_folders["trash"] = os.path.join(self.acquisition_dir, "trash")
        self.project_folders["trash_metadata"] = os.path.join(self.acquisition_dir, "trash_metadata")

        self.config_file = os.path.join(self.working_dir, "config.cfg")

        for f in self.project_folders:
            IO.put("{} path is {}".format(f, self.project_folders[f]))
            if not os.path.exists(self.project_folders[f]):
                IO.put("{} directory not found, creating from scratch.", "warn")
                os.makedirs(self.project_folders[f], exist_ok=True)

        IO.put("Config file is " + self.config_file)

        if not os.path.isfile(self.config_file):
            IO.put("Config file not found, creating default config file", "warn")
            with open(self.config_file, 'w') as f:
                f.write(DefaultConfigs.defaults)

        self.config = ConfigLoader.ConfigLoader()
        self.config.from_file(self.config_file)

        self.transaction_log = os.path.join(self.project_folders["logs"], "transaction.log")
        self.exception_log = os.path.join(self.project_folders["logs"], "exception.log")

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
        if self.args.service == "google_drive":
            instance = GoogleDrive.GoogleDrive(self)
            instance.sync()
        if self.args.service == "dropbox":
            instance = Dropbox.Dropbox(self)
            instance.sync()
        if self.args.service == "gmail":
            instance = GMail.GMail(self)
            instance.sync()


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

    def savedata(self, data, filepath, stream=True):
        try:
            with open(filepath, 'wb') as f:
                if stream:
                    shutil.copyfileobj(data, f)
                else:
                    f.write(data.encode())

        except http.client.IncompleteRead:
            # TODO: Check yourself before you wreck yourself
            print("OMG INCOMPLETE READ, WHAT DO?!")
            input()

