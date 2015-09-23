__author__ = 'aurcioli'
__author__ = 'aurcioli'
from onlinestorage import OnlineStorage
from common import Common
import json
import urllib.parse
import webbrowser
from datetime import datetime, timedelta
from downloader import Downloader
import os
from oi.IO import IO
from oauth2providers import OAuth2Providers
import base64
import mailbox
from email.mime.text import MIMEText

class GMail(OnlineStorage.OnlineStorage):
    threads = []
    verification = []
    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    # Get threads with includeSpamTrash=True
    # uses nextpagetoken

    def __init__(self, project):
        self.project = project
        self.oauth_provider = OAuth2Providers.OAuth2Provider(self, "google", "refresh_token")
        self.project.save("API_ENDPOINT", 'https://www.googleapis.com/gmail/v1')
        self.project.save("OAUTH_SCOPE", 'https://www.googleapis.com/auth/gmail.readonly')
        self.files = []
        self.file_size_bytes = 0
        super(GMail, self).__init__(self, project.name)

    def sync(self):
        d1 = datetime.now()
        self.d = Downloader.Downloader
        self.content_downloader = Downloader.Downloader

        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
            self.d = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._custom_save_file, self.oauth_provider.get_auth_header, self.project.threads)
            self.content_downloader = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_raw_mail, self.oauth_provider.get_auth_header, self.project.threads)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)

        self.initialize_items()
        cnt = len(self.threads)
        self.project.log("transaction", "Total threads queued for acquisition: {}".format(cnt), "info", True)
        self.metadata()

        for thread in self.threads:
            self.project.log("transaction", 'Calculating "{}"'.format(thread['snippet']), "info", True)
            download_uri = self.get_thread_uri(thread)
            savepath = ""
            self.d.put(Downloader.DownloadSlip(download_uri, thread, savepath, 'id'))

        self.d.start()
        self.d.wait_for_complete()
        self.project.log("transaction", "Total size of mail to be acquired is {}".format(Common.sizeof_fmt(self.file_size_bytes,"B")), "highlight", True)
        self.mbox_dir = os.path.join(self.project.acquisition_dir, "mbox")
        os.makedirs(self.mbox_dir, exist_ok=True)

        if self.project.args.prompt:
            IO.get("Press ENTER to begin acquisition...")
        self.content_downloader.start()
        self.content_downloader.wait_for_complete()

    def _save_raw_mail(self, data, slip):
        data = data.read().decode('utf-8')
        msg = json.loads(data)
        msg_data = msg["raw"]
        msg_data = base64.urlsafe_b64decode(msg_data).decode('utf-8')
        labels = msg["labelIds"]
        data_dir = self.project.project_folders["data"]
        for label in labels:
            mbox = mailbox.mbox(os.path.join(self.mbox_dir, label))
            mbox_msg = mailbox.mboxMessage()
            mbox_msg.set_payload(msg_data, charset='utf-8')
            mbox.add(mbox_msg)
            label_path = os.path.join(data_dir, label)
            save_path = os.path.join(label_path, slip.savepath)
            save_path = Common.assert_path(save_path, self.project)
            if save_path:
                if not os.path.isdir(os.path.dirname(save_path)):
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                self.project.savedata(msg_data, save_path, False)
                self.project.log("transaction", "Saved file to " + save_path, "info", True)
            for part in mbox_msg.walk():
                print(part.get_content_type())
                input()
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue
                att_name = part.get_filename()
                if att_name:
                    att_dir = os.path.join(label_path, slip.savepath[:slip.savepath.index('.')])
                    att_path = os.path.join(att_dir, att_name)
                    self.project.savedata(part.get_payload(decode=True), att_path, False)
                    self.project.log("transaction", "Saved attachment to " + save_path, "info", True)
            mbox.flush()

    def _custom_save_file(self, data, slip):
        data = data.read().decode()
        json_data = json.loads(data)
        if "messages" in json_data:
            for message in json_data["messages"]:
                download_uri = self.get_message_uri(message)
                _filetitle = message["id"] + ".txt"
                filetitle = Common.safe_file_name(_filetitle)
                self.file_size_bytes += int(message["sizeEstimate"])
                if filetitle != filetitle:
                    self.project.log("exception", "Normalized '{}' to '{}'".format(_filetitle, filetitle),"warning", True)
                self.content_downloader.put(Downloader.DownloadSlip(download_uri, message, filetitle, "snippet"))

    def get_thread_uri(self, thread):
        id = thread['id']
        t_uri = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/threads/{}?format=minimal".format(id))
        return t_uri

    def get_message_uri(self, message):
        id = message['id']
        m_uri = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/messages/{}?format=raw".format(id))
        return m_uri
    # def get_message_download_uri(self, message):
    #     id = message['id']
    #     m_uri = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/messages/{}?format=raw")

    def metadata(self):
        pass

    def initialize_items(self):
        self.threads = []
        self.project.log("transaction", "API Endpoint is {}".format(self.project.config['API_ENDPOINT']), "info", True)
        self._build_fs(Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/threads?userId=me&includeSpamTrash=true"))

    def _build_fs(self, link):
        self.project.log("transaction", "Calculating total GMail items...", "info", True)
        response = Common.webrequest(link, self.oauth_provider.get_auth_header(), self.oauth_provider.http_intercept)
        json_response = json.loads(response)

        if 'nextPageToken' in json_response:
            threads = json_response['threads']
            self._add_items_to_threads(threads)
            next_url = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/threads?userId=me&includeSpamTrash=true&pageToken={}".format(json_response['nextPageToken']))
            self._build_fs(next_url)
        else:
            items = json_response['threads']
            self._add_items_to_threads(items)

    def _add_items_to_threads(self, items):
        for i in items:
            self.threads.append(i)


