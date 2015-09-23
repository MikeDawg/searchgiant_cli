__author__ = 'aurcioli'
from onlinestorage import OnlineStorage
from common import Common
import json
import urllib.parse
from datetime import datetime, timedelta
from downloader import Downloader
import os
from oi.IO import IO
from oauth2providers import OAuth2Providers

# TODO: Needs to download folder metadata too
class Dropbox(OnlineStorage.OnlineStorage):
    files = []
    verification = []
    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    def __init__(self, project):
        self.project = project
        self.oauth_provider = OAuth2Providers.OAuth2Provider(self, "dropbox", 'access_token')
        self.files = []
        self.file_size_bytes = 0
        # if 'OAUTH' in self.project.config:
        #     self.oauth = self.project.config['OAUTH']
        super(Dropbox, self).__init__(self, project.name)

    def metadata(self):
        pass

    def verify(self):
        pass

    def sync(self):
        d1 = datetime.now()
        d = Downloader.Downloader
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
            d = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_file, self.oauth_provider.get_auth_header, self.project.threads)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)
        self.initialize_items()
        cnt = len(self.files)

        self.project.log("transaction", "Total items queued for acquisition: " + str(cnt), "info", True)
        with open("files.json",'w') as f:
            f.write(json.dumps(self.files, sort_keys=True, indent=4))
        self.metadata()
        self.verification = []
        # TODO: Metadata is not full
        # TODO: Original file listing (/delta) does not return folder hashes
        # TODO: or deleted files
        for file in self.files:

            self.project.log("transaction", "Calculating " + file['path'], "info", True)
            if file['is_dir'] == False:
                download_uri = lambda f=file: self._get_download_uri(f)
                parentmap = self._get_parent_mapping(file)
                filetitle = self._get_file_name(file)
                orig = os.path.basename(file['path'])
                if filetitle != orig:
                    self.project.log("exception", "Normalized '{}' to '{}'".format(orig, filetitle), "warning", True)

                save_download_path = Common.assert_path(os.path.normpath(os.path.join(os.path.join(self.project.project_folders['data'], parentmap), filetitle)), self.project)
                if self.project.args.mode == "full":
                    if save_download_path:
                        self.project.log("transaction", "Queueing {} for download...".format(orig), "info", True)
                        d.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'path'))
                        if 'bytes' in file:
                            self.file_size_bytes += int(file['bytes'])
            else:
                verification = {}

        self.project.log("transaction", "Total size of files to be acquired is {}".format(Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)
        if self.project.args.prompt:
            IO.get("Press ENTER to begin acquisition...")

        d.start()
        d.wait_for_complete()
        d2 = datetime.now()
        delt = d2 - d1
        self.verify()
        self.project.log("transaction", "Acquisition completed in {}".format(str(delt)), "highlight", True)

    def _get_parent_mapping(self, file):
        # Nothing difficult about this one.
        dir = os.path.dirname(file['path'])
        return dir.replace('/', os.sep)[1:]

    def _get_file_name(self, file):
        fname = os.path.basename(file['path'])
        return Common.safe_file_name(fname)

    def _get_download_uri(self, file):
        response = Common.webrequest(self.oauth_provider.config['API_ENDPOINT'] + '/media/auto' + file['path'], self.oauth_provider.get_auth_header(), self.oauth_provider.http_intercept)
        json_response = json.loads(response)
        if 'url' in json_response:
            return json_response['url']
        else:
            return None

    def account_info(self):
        # TODO: Implement for this and GoogleDrive
        pass

    # def _save_file(self, data, slip):
    #     # TODO : Where else to put this vvv checkforpause
    #     Common.check_for_pause(self.project)
    #     savepath = slip.savepath
    #     file_item = slip.item
    #     path_to_create = os.path.dirname(savepath)
    #     if not os.path.isdir(path_to_create):
    #         os.makedirs(path_to_create, exist_ok=True)
    #     if data:
    #         self.project.savedata(data, savepath)
    #         self.project.log("transaction", "Saved file to " + savepath, "info", True)
    #     else:
    #         self.project.log("transaction", "Saving metadata to " + savepath, "info", True)
    #         data = json.dumps(file_item, sort_keys=True, indent=4)
    #         self.project.savedata(data, savepath, False)
    #
    #     pass

    def initialize_items(self):
        self.files = []
        self.project.log("transaction", "API Endpoint is " + self.oauth_provider.config['API_ENDPOINT'], "info", True)
        link = self.oauth_provider.config['API_ENDPOINT'] + '/delta'
        self._build_fs(link)

    def _build_fs(self, link, cursor = None):
        self.project.log("transaction", "Calculating total dropbox items...", "info", True)
        if cursor:
            response = Common.webrequest(link, self.oauth_provider.get_auth_header(), self.oauth_provider.http_intercept, urllib.parse.urlencode({'cursor': cursor}))
        else:
            response = Common.webrequest(link, self.oauth_provider.get_auth_header(), self.oauth_provider.http_intercept, "")
        json_response = json.loads(response)
        has_more = json_response['has_more']
        cursor = json_response['cursor']
        for item in json_response['entries']:
            self.files.append(item[1])
        if has_more:
            self._build_fs(link, cursor)
    #
    # def http_intercept(self, err):
    #     if err.code == 401 or err.code == 400:
    #         self._authorize()
    #         return self.get_auth_header()
    #     else:
    #         self.project.log("exception", "Error and system does not know how to handle: " + str(err.code), "critical",
    #                          True)
    #
    # def get_auth_header(self):
    #     return {'Authorization': 'Bearer ' + self.oauth['access_token']}
