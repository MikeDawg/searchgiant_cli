__author__ = 'aurcioli'
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

# TODO: Needs to download folder metadata too
class Dropbox(OnlineStorage.OnlineStorage):
    files = []
    verification = []
    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    def __init__(self, project):
        self.project = project
        self.files = []
        self.file_size_bytes = 0
        if 'OAUTH' in self.project.config:
            self.oauth = self.project.config['OAUTH']
        super(Dropbox, self).__init__(self.project.config['API_ENDPOINT'], project.name)

    def _authorize(self):
        self.project.log("transaction", "Initiating OAUTH 2 Protocol with " + self.project.config['TOKEN_ENDPOINT'], "info", True)
        if not self.oauth["access_token"]:
            self.project.log("transaction", "No valid access token found..", "warning", True)
            if not self.project.config['CLIENT_ID'] or not self.project.config['CLIENT_SECRET']:
                self.project.log("transaction", "No app key or app secret. Ask for user input..", "warning", True)
                IO.put("You must configure your account for OAUTH 2.0")
                IO.put("Please visit https://www.dropbox.com/developers/apps")
                IO.put("& create an application.")
                try:
                    webbrowser.open("https://www.dropbox.com/developers/apps")
                except:
                    pass

                app_key = IO.get("App Key:")
                app_secret = IO.get("App Secret:")
                self.project.save("CLIENT_ID", app_key)
                self.project.save("CLIENT_SECRET", app_secret)
                self.project.log("transaction", "Received app key and app secret from user ({}) ({})".format(app_key,app_secret),"info",True)
                # Step 1
                self.get_access_token(app_key, app_secret)
            else:
                self.get_access_token(self.project.config['CLIENT_ID'], self.project.config['CLIENT_SECRET'])

        self.project.log("transaction", "Authorization complete", "info", True)

    def get_access_token(self, app_key, app_secret):
        response_type = 'code'
        query_string = ({'response_type': response_type, 'client_id': app_key})
        params = urllib.parse.urlencode(query_string)
        step1 = self.project.config['OAUTH_ENDPOINT'] + '?' + params
        try:
            webbrowser.open(step1)
        except:
            IO.put("Error launching webbrowser to receive authorization code. You must manually visit the following url and enter the code at this page: \n{}".format(step1),"highlight")

        code = IO.get("Authorization Code:")
        self.project.log("transaction", "Auth code received: ({})".format(code), "info", True)

        #Step 2
        query_string = ({'code': code, 'grant_type': 'authorization_code', 'client_id': app_key, 'client_secret': app_secret})
        params = urllib.parse.urlencode(query_string)
        response = Common.webrequest(self.project.config['TOKEN_ENDPOINT'], {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'}, self.http_intercept, params)
        json_response = json.loads(response)
        self._parse_token(json_response)
        self.project.save("OAUTH", self.oauth)

    def _parse_token(self, response):
        self.oauth['access_token'] = response['access_token']
        self.oauth['uid'] = response['uid']

    def metadata(self):
        pass

    def sync(self):
        pass
        d1 = datetime.now()
        d = Downloader.Downloader
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full synchronization initiated", "info", True)
            d = Downloader.Downloader(self.project, self.http_intercept, self._save_file, self.get_auth_header, self.project.threads)
        else:
            self.project.log("transaction", "Metadata synchronization initiated", "info", True)
        self.initialize_items()
        cnt = len(self.files)

        self.project.log("transaction", "Total items queued for synchronization: " + str(cnt), "info", True)
        with open("files.json",'w') as f:
            f.write(json.dumps(self.files, sort_keys=True, indent=4))
        self.metadata()
        self.verification = []
        # TODO: Metadata is not full
        # TODO: Original file listing (/delta) does not return folder hashes
        # TODO: or deleted files
        for file in self.files:
            self.project.log("transaction", "Calculating " + file['path'])
            if file['is_dir'] == False:
                download_uri = self._get_download_uri(file)
                parentmap = self._get_parent_mapping(file)
                filetitle = self._get_file_name(file)
                orig = os.path.basename(file['path'])
                if filetitle != orig:
                    self.project.log("exception", "Normalized '{}' to '{}'", "warning".format(orig, filetitle), True)

                save_download_path = Common.assert_path(os.path.normpath(os.path.join(os.path.join(self.project.project_folders['data'], parentmap), filetitle)), self.project)
                if self.project.args.mode == "full":
                    if save_download_path:
                        self.project.log("transaction", "Queueing {} for download...".format(orig), "info", True)
                        d.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'path'))
                        if 'bytes' in file:
                            self.file_size_bytes += int(file['bytes'])

            else:
                verification = {}

    def _get_parent_mapping(self, file):
        # Nothing difficult about this one.
        dir = os.path.dirname(file['path'])
        return dir.replace('/', os.sep)

    def _get_file_name(self, file):
        fname = os.path.basename(file['path'])
        return Common.safe_file_name(fname)

    def _get_download_uri(self, file):
        response = Common.webrequest(self.project.config['API_ENDPOINT'] + '/media/auto' + file['path'], self.get_auth_header(), self.http_intercept)
        json_response = json.loads(response)
        if 'url' in json_response:
            return json_response['url']
        else:
            return None

    def account_info(self):
        # TODO: Implement for this and GoogleDrive
        pass

    def _save_file(self):
        pass

    def initialize_items(self):
        self.files = []
        self.project.log("transaction", "API Endpoint is " + self.project.config['API_ENDPOINT'], "info", True)
        link = self.project.config['API_ENDPOINT'] + '/delta'
        self._build_fs(link)

    def _build_fs(self, link, cursor = None):
        self.project.log("transaction", "Calculating total dropbox items...", "info", True)
        if cursor:
            response = Common.webrequest(link, self.get_auth_header(), self.http_intercept, urllib.parse.urlencode({'cursor': cursor}))
        else:
            response = Common.webrequest(link, self.get_auth_header(), self.http_intercept, "")
        json_response = json.loads(response)
        has_more = json_response['has_more']
        cursor = json_response['cursor']
        for item in json_response['entries']:
            self.files.append(item)
        if has_more:
            self._build_fs(link, cursor)

    def http_intercept(self, err):
        if err.code == 401 or err.code == 400:
            self._authorize()
            return self.get_auth_header()
        else:
            self.project.log("exception", "Error and system does not know how to handle: " + str(err.code), "critical",
                             True)

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.oauth['access_token']}
