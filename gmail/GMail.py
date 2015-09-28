__author__ = 'aurcioli'
__author__ = 'aurcioli'
import json
from datetime import datetime
import os
import base64
import mailbox
import email

from onlinestorage import OnlineStorage
from common import Common
from downloader import Downloader
from oi.IO import IO
from oauth2providers import OAuth2Providers
import time

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
        self.meta_downloader = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_metadata, self.oauth_provider.get_auth_header, self.project.threads)

        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
            self.d = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._redirect_messages_to_save, self.oauth_provider.get_auth_header, self.project.threads)
            self.content_downloader = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_raw_mail, self.oauth_provider.get_auth_header, self.project.threads)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)

        self.initialize_items()
        cnt = len(self.threads)
        self.project.log("transaction", "Total threads queued for acquisition: {}".format(cnt), "info", True)
        self.metadata()

        for thread in self.threads:
            self.project.log("transaction", 'Calculating "{}"'.format(thread['snippet']), "info", True)
            savepath = ""
            if self.project.args.mode == "full":
                download_uri = self.get_thread_uri(thread, "minimal")
                self.d.put(Downloader.DownloadSlip(download_uri, thread, savepath, 'id'))

            meta_uri = self.get_thread_uri(thread, "metadata")
            self.meta_downloader.put(Downloader.DownloadSlip(meta_uri, thread, savepath, 'id'))

        if self.project.args.mode == "full":
            self.d.start()
            self.d.wait_for_complete()
            self.project.log("transaction", "Total size of mail to be acquired is {}".format(Common.sizeof_fmt(self.file_size_bytes,"B")), "highlight", True)
            self.mbox_dir = os.path.join(self.project.acquisition_dir, "mbox")
            os.makedirs(self.mbox_dir, exist_ok=True)

        if self.project.args.prompt:
            IO.get("Press ENTER to begin acquisition...")

        if self.project.args.mode == "full":
            self.content_downloader.start()
            self.content_downloader.wait_for_complete()

        self.meta_downloader.start()
        self.meta_downloader.wait_for_complete()

        d2 = datetime.now()
        delt = d2 - d1
        self.project.log("transaction", "Acquisition completed in {}".format(str(delt)), "highlight", True)

    def _save_metadata(self, data, slip):
        data = data.read().decode('utf-8')
        thread = json.loads(data)
        f = open(self.metadata_file, 'ab')
        for message in thread['messages']:
            for label in message['labelIds']:
                label_dir = os.path.join(self.project.project_folders['metadata'], label)
                thread_dir = os.path.join(label_dir, thread['id'])
                message_dir = os.path.join(thread_dir, message['id'])
                msg_metadata_path = os.path.join(message_dir, message['id'] + ".json")
                msg_metadata_path = Common.assert_path(msg_metadata_path, self.project)
                # Save metadata of each message individually, inside label/thread/message directory
                if msg_metadata_path:
                    os.makedirs(message_dir, exist_ok=True)
                    self.project.savedata(json.dumps(message, sort_keys=True, indent=4), msg_metadata_path, False)
                    self.project.log("transaction", "Saving metadata to {}".format(msg_metadata_path), "info", True)
                thread_metadata_path = os.path.join(thread_dir, thread['id'] + ".json")

                # Save metadata of each thread individually inside label/thread directory
                thread_metadata_path = Common.assert_path(thread_metadata_path, self.project)
                if thread_metadata_path:
                    os.makedirs(thread_dir, exist_ok=True)
                    self.project.savedata(json.dumps(thread, sort_keys=True, indent=4), thread_metadata_path, False)
                    self.project.log("transaction", "Saving metadata to {}".format(thread_metadata_path), "info", True)
            headers = message['payload']['headers']
            label_list = ",".join(message['labelIds'])
            internal_date = message['internalDate']
            internal_date = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(internal_date) / 1000))
            header_date = 'N/A' if not self.extract_header_value(headers, 'Date') else self.extract_header_value(headers, 'Date')
            header_to = 'N/A' if not self.extract_header_value(headers, 'To') else self.extract_header_value(headers, 'To')
            header_from = 'N/A' if not self.extract_header_value(headers, 'From') else self.extract_header_value(headers, 'From')
            header_subject = 'N/A' if not self.extract_header_value(headers, 'Subject') else self.extract_header_value(headers, 'Subject')
            snippet = message['snippet']
            thread_id = thread['id']
            f.write('"{id}","{internaldate}","{labels}","{headerdate}","{to}","{xfrom}","{subject}","{snippet}","{threadid}"{sep}'.format(id=message['id'],internaldate=internal_date,labels=label_list,headerdate=header_date,to=header_to,xfrom=header_from,subject=header_subject,snippet=snippet,threadid=thread_id,sep=os.linesep).encode('utf-8'))
        f.close()

    def extract_header_value(self, l, name):
        for kv in l:
            if kv['name'] == name:
                return kv['value']

    def _save_raw_mail(self, data, slip):
        data = data.read().decode('utf-8')
        msg = json.loads(data)
        msg_data = msg["raw"]
        msg_data = base64.urlsafe_b64decode(msg_data).decode('utf-8')
        labels = msg["labelIds"]
        data_dir = self.project.project_folders["data"]
        for label in labels:
            mbox = mailbox.mbox(os.path.join(self.mbox_dir, label))
            mbox_msg = email.message_from_bytes(msg_data.encode(), mailbox.mboxMessage)
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
                content_disposition =part.get("Content-Disposition", None)
                if content_disposition:
                    data = part.get_payload(decode=True)
                    att_name = part.get_filename()
                    if att_name:
                        att_dir = os.path.join(label_path, slip.savepath[:slip.savepath.index('.')])
                        att_path = os.path.join(att_dir, att_name)
                        os.makedirs(att_dir, exist_ok=True)
                        with open(att_path, 'wb') as f:
                            f.write(data)
                        self.project.log("transaction", "Saved attachment to " + save_path, "info", True)
            mbox.flush()

    def _redirect_messages_to_save(self, data, slip):
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

    def get_thread_uri(self, thread, format):
        id = thread['id']
        t_uri = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/threads/{}?format={}".format(id, format))
        return t_uri

    def get_message_uri(self, message):
        id = message['id']
        m_uri = Common.joinurl(self.project.config['API_ENDPOINT'], "users/me/messages/{}?format=raw".format(id))
        return m_uri

    def metadata(self):
        msg_list_path = os.path.join(self.project.working_dir, Common.timely_filename("message_list",".csv"))
        with open(msg_list_path, 'w') as f:
            f.write("id,internalDate,labels,headerDate,To,From,Subject,snippet,threadId\n")
        self.metadata_file = msg_list_path

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


