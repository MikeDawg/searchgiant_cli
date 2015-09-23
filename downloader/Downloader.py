__author__ = 'alexander'
from queue import Queue
from common import Common
from threading import Thread
import threading
import time

class DownloadSlip:

    def __init__(self, url, item, savepath, fname_key):
        self.url = url
        self.item = item
        self.savepath = savepath
        self.filename_key = fname_key

class Downloader(Queue):

    headers = ""
    storage_callback = None
    threads = 3

    def __init__(self, project, http_callback, storage_callback, get_headers, threads):

        self.project = project
        self.storage_callback = storage_callback
        self.headers = get_headers
        self.threads = threads
        self.http_callback = http_callback
        super(Downloader, self).__init__()

    def wait_for_complete(self):
        running = True
        while not self.empty():
            time.sleep(3)
        while running:
            download_thread = False
            for t in threading.enumerate():
                if 'Downloading' in t.name:
                    download_thread = True
            if not download_thread:
                running = False
            time.sleep(3)

    def start(self):
        for i in range(0, self.threads):
            t = Thread(target=self._downloader)
            t.daemon = True
            t.name = "Download thread " + str(i)
            t.start()

    def _downloader(self):
        while (not self.empty()) and (not self.project.shutdown_signal):
            t = threading.current_thread()
            Common.check_for_pause(self.project)
            slip = self.get()
            if callable(slip.url):
                file_url = slip.url()
            else:
                file_url = slip.url
            t.name = 'Downloading: ' + slip.item[slip.filename_key]
            self.project.log("transaction", "Downloading " + slip.item[slip.filename_key], "info", True)
            data = Common.webrequest(file_url, self.headers(), self.http_callback, None, False, True) # Response object gets passed to shutil.copyfileobj
            self.storage_callback(data, slip)
        if self.project.shutdown_signal:
            self.project.log("exception", "{} received shutdown signal. Stopping...".format(threading.current_thread().name), "warning")
        else:
            self.project.log("exception", "{} has completed.".format(threading.current_thread().name), "info")



