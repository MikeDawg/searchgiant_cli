
from onlinestorage import OnlineStorage
from common import Common
import json
import urllib.parse
import webbrowser
from datetime import datetime, timedelta
from downloader import Downloader
import os
import hashlib
from oi.IO import IO
import time


class GoogleDrive(OnlineStorage.OnlineStorage):

    files = []

    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    input_callback = None

    def __init__(self, project):

        self.project = project
        self.files = []
        self.file_size_bytes = 0
        if "OAUTH" in self.project.config:
            self.oauth = self.project.config['OAUTH']
        super(GoogleDrive, self).__init__(self.project.config['API_ENDPOINT'], project.name)

    def _authorize(self):
        self.project.log("transaction", "Initiating OAUTH 2 Protocol with " + self.project.config['TOKEN_ENDPOINT'], "info", True)
        if not self.oauth['refresh_token']:
            self.project.log("transaction", "No valid refresh token found..", "warning", True)
            if not self.project.config['CLIENT_ID'] or not self.project.config['CLIENT_SECRET']:
                self.project.log("transaction", "No client id or client secret. Asking for user input..", "warning", True)
                IO.put("You must configure your account for OAUTH 2.0")
                IO.put("Please visit https://console.developers.google.com/project")
                IO.put("& create an OAUTH 2.0 client ID under APIs & Auth > Credentials")
                try:
                    webbrowser.open("http://console.developers.google.com/project")
                except:
                    pass
                client_id = IO.get("Client ID:")
                client_secret = IO.get("Client Secret:")
                self.project.save("CLIENT_ID", client_id)
                self.project.save("CLIENT_SECRET", client_secret)
                self.project.log("transaction", "Received client_id and client_secret from user (" + client_id + ") (" + client_id + ")", "info", True)

            # Step 1
            response_type = 'code'
            query_string = (
            {'redirect_uri': self.project.config['REDIRECT_URI'], 'response_type': response_type, 'client_id': self.project.config['CLIENT_ID'],
             'scope': self.project.config['OAUTH_SCOPE'], 'approval_prompt': 'force', 'access_type': 'offline'})
            params = urllib.parse.urlencode(query_string)
            step1 = self.project.config['OAUTH_ENDPOINT'] + '?' + params
            try:
                webbrowser.open(step1)
            except:
                pass
            code = IO.get("Authorization Code:")
            self.project.log("transaction", "Auth code received: (" + code + ")", "info", True)
            # Step 2
            query_string = ({'code': code, 'redirect_uri': self.project.config['REDIRECT_URI'], 'client_id': self.project.config['CLIENT_ID'], 'scope': '',
                             'client_secret': self.project.config['CLIENT_SECRET'], 'grant_type': 'authorization_code'})
            params = urllib.parse.urlencode(query_string)
            response = Common.webrequest(self.project.config['TOKEN_ENDPOINT'],
                                         {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'},
                                         self.http_intercept, params)
            json_response = json.loads(response)
            self._parse_token(json_response)
        else:
            self._refresh()

        self.project.save("OAUTH", self.oauth)
        self.project.log("transaction", "Authorization complete", "info", True)

    def _refresh(self):
        query_string = ({'client_secret': self.project.config['CLIENT_SECRET'], 'grant_type': 'refresh_token',
                         'refresh_token': self.oauth['refresh_token'], 'client_id': self.project.config['CLIENT_ID']})
        params = urllib.parse.urlencode(query_string)
        response = Common.webrequest(self.project.config['TOKEN_ENDPOINT'],
                                     {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'},
                                     self.http_intercept, params)
        json_response = json.loads(response)
        self._parse_token(json_response)

    def metadata(self):
        pass

    def full_sync(self):
        self.project.log("transaction", "Full synchronization initiated", "info", True)
        self.project.log("transaction", "API Endpoint is " + self.project.config['API_ENDPOINT'], "info", True)
        self.files = []

        self._get_items(Common.joinurl(self.project.config['API_ENDPOINT'], "files?maxResults=0"))
        cnt = len(self.files)
        self.project.log("transaction", "Total files queued for synchronization: " + str(cnt), "info", True)
        d = Downloader.Downloader(self.project, self.http_intercept, self._save_file, self.get_auth_header, self.project.threads)

        for file in self.files:
            self.project.log("transaction", "Calculating " + file['title'], "info", True)
            download_uri = self._get_download_url(file)
            parentmap = self._get_parent_mapping(file, self.files)
            path_to_create = os.path.normpath(os.path.join(self.project.data_dir, parentmap))
            filetitle = Common.safefilename(file['title'])
            if filetitle != file['title']:
                self.project.log("exception", "Normalized '" + file['title'] + "' to '" + filetitle + "'", "warning", True)

            savepath = os.path.join(path_to_create, filetitle)

            download_file = True
            if os.path.isfile(savepath):
                if 'md5Checksum' in file:
                    if Common.hashfile(open(savepath,'rb'),hashlib.md5()) == file['md5Checksum']:
                        download_file = False
                        self.project.log("exception", "Local and remote hash matches for " + file['title'] + " ... Skipping download", "warning", True)
                    else:
                        self.project.log("exception", "Local and remote hash differs for " + file['title'] + " ... Queuing for download", "critical", True)

            if download_file and download_uri:
                self.project.log("transaction", "Queueing " + file['title'] + " for download...", "info", True)
                d.put(Downloader.DownloadSlip(download_uri, file, savepath))
                if 'fileSize' in file:
                    self.file_size_bytes += int(file['fileSize'])
        self.project.log("transaction","Total size of files to be synchronized is {}".format(Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)
        if self.project.args.prompt:
            IO.get("Press ENTER to begin synchronization...")
        d.start()
        while not d.empty():
            time.sleep(1)

    def _save_file(self, data, slip):
        Common.check_for_pause(self.project)
        savepath = slip.savepath
        file_item = slip.item
        path_to_create = os.path.dirname(savepath)

        if len(savepath) > 255:
            self.project.log("exception", "File name is too long to save. File was NOT downloaded: " + savepath, "critical", True)

        else:
            if not os.path.isdir(path_to_create):
                os.makedirs(path_to_create, exist_ok=True)
            if data:
                self.project.log("transaction", "Saving file " + savepath, "info", True)
                self.project.savedata(data, savepath)
            else:
                self.project.log("transaction", "Saving metadata to " + savepath, "info", True)
                data = json.dumps(file_item, sort_keys=True, indent=4)
                self.project.savedata(data, savepath)

    def _get_parent_mapping(self, i, items):
        # This is the secret sauce
        folderpath = ""
        while 'parents' in i or len(i['parents']) != 0:
            for p in i['parents']:
                if p['isRoot'] == True:
                    return folderpath
                else:
                    item = self._get_item_by_id(p['id'], items)
                    if item is not None:
                        folderpath = os.path.join(self._get_parent_mapping(item, items), item['title'])
                        return folderpath
                    else:
                        return folderpath
            return folderpath
        return folderpath

    def _get_item_by_id(self, f_id, items):
        for i in items:
            if i['id'] == f_id:
                return i
        return None

    def _get_download_url(self, file):
        preferred = "application/pdf"
        if 'downloadUrl' in file:
            return file['downloadUrl']
        if 'exportLinks' in file:
            if preferred in file['exportLinks']:
                return file['exportLinks'][preferred]
        if "file" in file:
            return file[0]
        return None

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.oauth['access_token']}

    def _get_items(self, link):
        self.project.log("transaction", "Calculating total drive items...", "info", True)
        response = Common.webrequest(link, self.get_auth_header(), self.http_intercept)
        json_response = json.loads(response)

        if 'nextLink' in json_response:
            items = json_response['items']
            self._add_items_to_files(items)
            self._get_items(json_response['nextLink'])
        else:
            items = json_response['items']
            self._add_items_to_files(items)

    def _add_items_to_files(self, items):
        for i in items:
            self.files.append(i)

    def _parse_token(self, response):
        self.oauth['access_token'] = response['access_token']
        self.oauth['expires_in'] = response['expires_in']
        expire_time = datetime.utcnow() + timedelta(0, int(self.oauth['expires_in']))
        self.oauth['expire_time'] = str(expire_time.timestamp())
        if 'refresh_token' in response:
            self.oauth['refresh_token'] = response['refresh_token']

    def http_intercept(self, err):
        if err.code == 401:
            self._authorize()
            return self.get_auth_header()
        else:
            self.project.log("exception", "Error and system does not know how to handle: " +str(err.code), "critical", True)

