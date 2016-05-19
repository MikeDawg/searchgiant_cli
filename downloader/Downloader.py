__author__ = 'alexander'
from queue import Queue
from threading import Thread
import threading
import time
import urllib
import queue

from common import Common


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
        self.finished_queuing = False
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
            time.sleep(0.001)

    def start(self):
        for i in range(0, self.threads):
            t = Thread(target=self._downloader)
            t.daemon = True
            t.name = "Download thread " + str(i)
            self.project.log("transaction", "Download thread {} starting".format(i), "warning")
            t.start()


    def _downloader(self):
        while (((self.empty() == False) or (self.finished_queuing == False)) and self.project.shutdown_signal == False):
            self.project.log("transaction", "Download thread {} started".format(threading.current_thread().name), "warning")
            t = threading.current_thread()
            Common.check_for_pause(self.project)
            try:
                slip = self.get(block=False, timeout=3)
                if callable(slip.url):
                    file_url = slip.url()
                else:
                    file_url = slip.url
                t.name = 'Downloading: ' + slip.item[slip.filename_key]
                self.project.log("transaction", "Downloading " + slip.item[slip.filename_key], "info", True)
                try:
                    data = Common.webrequest(file_url, self.headers(), self.http_callback, None, False, True) # Response object gets passed to shutil.copyfileobj
                    self.storage_callback(data, slip)
                except urllib.error.HTTPError as err:
                    self.project.log("exception", "{} failed to download - HTTPError {}".format(slip.item[slip.filename_key], err.code), "warning")
            except queue.Empty:
                pass

        if self.project.shutdown_signal:
            self.project.log("exception", "{} received shutdown signal. Stopping...".format(threading.current_thread().name), "warning")
        else:
            self.project.log("transaction", "{} has completed.".format(threading.current_thread().name), "info")







