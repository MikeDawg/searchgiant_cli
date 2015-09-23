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


class OAuth2Provider:
    default = {
        "google": {
            "TOKEN_ENDPOINT": 'https://accounts.google.com/o/oauth2/token',
            "OAUTH_ENDPOINT": 'https://accounts.google.com/o/oauth2/auth',
            "API_VERSION": 'v2',
            "REDIRECT_URI": 'urn:ietf:wg:oauth:2.0:oob',
            "OAUTH_DASHBOARD": 'https://console.developers.google.com/project',
            "CLIENT_ID_ALIAS": "Client ID",
            "CLIENT_SECRET_ALIAS": "Client Secret"

        },
        "dropbox": {
            "TOKEN_ENDPOINT": 'https://api.dropboxapi.com/1/oauth2/token',
            "OAUTH_ENDPOINT": 'https://www.dropbox.com/1/oauth2/authorize',
            "API_ENDPOINT": 'https://api.dropboxapi.com/1',
            "OAUTH_DASHBOARD": 'https://www.dropbox.com/developers/apps',
            "CONTENT_ENDPOINT": "https://content.dropboxapi.com/1",
            "CLIENT_ID_ALIAS": "App Key",
            "CLIENT_SECRET_ALIAS": "App Secret"
        }
    }


    provider = ""
    oauth = {"access_token": "",
              "refresh_token": "",
              "expires_in:": 0}
    def __init__(self, app, provider, key_to_the_kingdom):
        self.app = app
        self.provider = provider
        self.project = app.project
        self.config = self.default[provider]
        if 'OAUTH' in self.project.config:
            self.oauth = self.project.config['OAUTH']
        self.key_to_the_kingdom = key_to_the_kingdom

    def authorize(self):
        self.project.log("transaction", "Initiating OAUTH2 Protocol with " + self.config['TOKEN_ENDPOINT'], "info",
                         True)
        key_exists = self.oauth.get(self.key_to_the_kingdom)
        if not key_exists:
            self.project.log("transaction", "No valid {} found...".format(self.key_to_the_kingdom), "warning", True)
            c_id = self.project.config.get("CLIENT_ID")
            c_secret = self.project.config.get("CLIENT_SECRET")
            if not c_id or not c_secret:
                self.project.log("transaction", "No CLIENT_ID or CLIENT_SECRET. Asking for user input", "warning", True)

                IO.put("You must configure your account for OAUTH 2.0")
                IO.put("Please visit {}".format(self.config["OAUTH_DASHBOARD"]))
                IO.put("& Create an OAUTH 2 API Application")

                try:
                    webbrowser.open(self.config["OAUTH_DASHBOARD"])
                except:
                    IO.put("Please visit this URL: {}".format(self.config["OAUTH_DASHBOARD"]))

                client_id = IO.get("{}:".format(self.config["CLIENT_ID_ALIAS"]))
                client_secret = IO.get("{}:".format(self.config["CLIENT_SECRET_ALIAS"]))

                self.project.save("CLIENT_ID", client_id)
                self.project.save("CLIENT_SECRET", client_secret)

                self.project.log("transaction",
                                 "Received {} and {} from user ({}) ({})".format(self.config['CLIENT_ID_ALIAS'],
                                                                                 self.config['CLIENT_SECRET_ALIAS'],
                                                                                 client_id, client_secret), "info",
                                 True)
                self.get_access_token(client_id, client_secret)
            else:
                self.get_access_token(self.project.config['CLIENT_ID'], self.project.config['CLIENT_SECRET'])
        else:
            self.refresh(self.project.config['CLIENT_ID'], self.project.config['CLIENT_SECRET'])

        self.project.save("OAUTH", self.oauth)
        self.project.log("transaction","Authorization completed", "info", True)

    def refresh(self, client_id, client_secret):
        if self.provider == "google":
            query_string = ({'client_secret': client_secret, 'grant_type': 'refresh_token',
                         'refresh_token': self.oauth['refresh_token'], 'client_id': client_id})
            params = urllib.parse.urlencode(query_string)
            response = Common.webrequest(self.config['TOKEN_ENDPOINT'],
                                         {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'},
                                         self.http_intercept, params)
            json_response = json.loads(response)
            self.parse_token(json_response)
        else:
            self.project.log("exception","WARNING - Authorization is being rejected by host API.", "critical", True)

    def get_access_token(self, client_id, client_secret):
        response_type = 'code'
        query_string = {}
        if self.provider == "google":
            query_string = (
                {'redirect_uri': self.config['REDIRECT_URI'], 'response_type': response_type,
                 'client_id': client_id,
                 'scope': self.project.config['OAUTH_SCOPE'], 'approval_prompt': 'force', 'access_type': 'offline'})
        elif self.provider == "dropbox":
            query_string = ({'response_type': response_type, 'client_id': client_id})

        params = urllib.parse.urlencode(query_string)
        step1 = self.config['OAUTH_ENDPOINT'] + '?' + params
        try:
            webbrowser.open(step1)
        except:
            IO.put("Please visit this URL in your browser to continue authorization:\n{}".format(step1))

        code = IO.get("Authorization Code:")
        query_string = ({'code': code, 'grant_type': 'authorization_code', 'client_id': client_id, 'client_secret': client_secret})

        if self.provider == "google":
            query_string['scope'] = ''
            query_string['redirect_uri'] = self.config['REDIRECT_URI']

        params = urllib.parse.urlencode(query_string)
        response = Common.webrequest(self.config['TOKEN_ENDPOINT'], {'content-type': 'application/x-www-form-urlencoded;charset=utf-8'}, self.http_intercept, params)
        json_response = json.loads(response)
        self.parse_token(json_response)
        self.project.save("OAUTH", self.oauth)

    def parse_token(self, response):
        self.oauth = response

    def http_intercept(self, err):
        if self.provider == "google":
            if err.code == 401:
                self.authorize()
                return self.get_auth_header()
            if err.code == 503:
                self.project.log("warning", "API Quota reached", "critical", True)
                # TODO: FIX Behavior with http_error
        elif self.provider == "dropbox":
            if err.code == 401 or err.code == 400:
                self.authorize()
                return self.get_auth_header()
        self.http_error(err)

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.oauth['access_token']}

    def http_error(self, err):
        self.project.log("exception", "HTTP Error: {} - Unhandled".format(err.code), "critical", True)

