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
    file = []
    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    def __init__(self, project):
        self.project = project
        self.files = []
        self.file_size_bytes= 0
        if 'OAUTH' in self.project.config:
            self.oauth = self.project.config['OAUTH']
        super(Dropbox, self).__init__(self.project.config['API_ENDPOINT'], project.name)


    def _authorize(self):
        self.project.log("transaction", "Initiating OAUTH 2 Protocol with " + self.project.config['TOKEN_ENDPOINT'], "info", True)
        if not self.oauth["access_token"]:
            self.project.log("transaction", "No valid access token found..", "warning", True)
            if not self.project.config['CLIENT_ID']: # or not self.project.config['CLIENT_SECRET']:
                self.project.log("transaction", "No app key or app secret. Ask for user input..", "warning", True)
                IO.put("You must configure your account for OAUTH 2.0")
                IO.put("Please visit https://www.dropbox.com/developers/apps")
                IO.put("& create an application.")
                try:
                    webbrowser.open("https://www.dropbox.com/developers/apps")
                except:
                    pass

                app_key = IO.get("App Key:")
                #app_secret = IO.get("App Secret:")
                self.project.save("CLIENT_ID", app_key)
                #self.project.save("CLIENT_SECRET", app_secret)
                #self.project.log("transaction", "Received app key and app secret from user ({}) ({})".format(app_key,app_secret),"info",True)
                self.project.log("transaction", "Received app key and app secret from user ({})".format(app_key),"info",True)
                # Step 1
                self.get_access_token(app_key)
            else:
                self.get_access_token(self.project.config['CLIENT_ID'])

        self.project.log("transaction", "Authorization complete", "info", True)

    def get_access_token(self, app_key):
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
        query_string = ({'code': code, 'grant_type': 'authorization_code'})
        params = urllib.parse.urlencode(query_string)
        response = Common.webrequest(self.project.config['TOKEN_ENDPOINT'], {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'}, self.http_intercept, params)
        json_response = json.loads(response)
        self._parse_token(json_response)
        self.project.save("OAUTH", self.oauth)

    def _parse_token(self, response):
        self.oauth['access_token'] = response['access_token']
        self.oauth['uid'] = response['uid']


    def sync(self):
        d1 = datetime.now()
        d = Downloader.Downloader
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full synchronization initiated", "info", True)
            d = Downloader.Downloader(self.project, self.http_intercept, self._save_file, self.get_auth_header, self.project.threads)
        else:
            self.project.log("transaction", "Metadata synchronization initiated", "info", True)

        self.initialize_items()

    def account_info(self):
        # TODO: Implement for this and GoogleDrive
        pass


    def initialize_items(self):
        self.files = []
        self.project.log("transaction", "API Endpoint is " + self.project.config['API_ENDPOINT'], "info", True)
        items = Common.webrequest(self.project.config['API_ENDPOINT'] + '/metadata/auto/?list=true&file_limit=25000', self.get_auth_header(), self.http_intercept)


    def http_intercept(self, err):
        if err.code == 401:
            self._authorize()
            return self.get_auth_header()
        else:
            self.project.log("exception", "Error and system does not know how to handle: " + str(err.code), "critical",
                             True)

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.oauth['access_token']}
