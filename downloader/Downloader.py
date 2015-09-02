__author__ = 'alexander'
from queue import Queue
from common import Common
from threading import Thread
import threading

class DownloadSlip:

    def __init__(self, url, item, savepath):
        self.url = url
        self.item = item
        self.savepath = savepath

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

    def start(self):
        for i in range(0, self.threads):
            t = Thread(target=self._downloader)
            t.daemon = True
            t.name = "Download thread " + str(i)
            t.start()

    def _downloader(self):
        while (not self.empty()) and (not self.project.shutdown_signal):
            Common.check_for_pause(self.project)
            slip = self.get()
            file_url = slip.url
            self.project.log("transaction", "Downloading " + file_url, "info", True)
            data = Common.webrequest(file_url, self.headers(), self.http_callback, None, False, True) # Response object gets passed to shutil.copyfileobj
            self.storage_callback(data, slip)
        if self.project.shutdown_signal:
            self.project.log("exception", "{} received shutdown signal. Stopping...".format(threading.current_thread().name), "warning")
        else:
            self.project.log("exception", "{} has completed.".format(threading.current_thread().name), "info")



