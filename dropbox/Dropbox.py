__author__ = 'aurcioli'
import json
import urllib.parse
from datetime import datetime
import os

from onlinestorage import OnlineStorage
from common import Common
from downloader import Downloader
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
        file_list_path = os.path.join(self.project.working_dir, Common.timely_filename("file_list",".csv"))
        with open(file_list_path, 'w') as csv:
            csv.write("filename,bytes,size,revision,modified,mimeType,isDir,root,clientmTime\n")
            for f in self.files:
                row = []
                row.append('None' if 'path' not in f else repr(f['path']))
                row.append('0' if 'bytes' not in f else repr(f['bytes']))
                row.append('None' if 'size' not in f else repr(f['size']))
                row.append('None' if 'revision' not in f else repr(f['revision']))
                row.append('None' if 'modified' not in f else repr(f['modified']))
                row.append('None' if 'mime_type' not in f else repr(f['mime_type']))
                row.append('None' if 'is_dir' not in f else repr(f['is_dir']))
                row.append('None' if 'root' not in f else repr(f['root']))
                row.append('None' if 'client_mtime' not in f else repr(f['client_mtime']))
                csv.write(','.join('"' + item + '"' for item in row) + "\n")
        csv.close()

    def verify(self):
        pass

    def sync(self):
        d1 = datetime.now()
        d = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_file, self.oauth_provider.get_auth_header, self.project.threads)
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)

        self.initialize_items()
        cnt = len(self.files)

        self.project.log("transaction", "Total items queued for acquisition: " + str(cnt), "info", True)
        self.metadata()

        for file in self.files:
            self.project.log("transaction", "Calculating " + file['path'], "info", True)

            if file['is_dir'] == False:
                download_uri = lambda f=file: self._get_download_uri(f)
                metadata_download_uri = self.oauth_provider.config['API_ENDPOINT'] + '/metadata/auto' + file['path']
                parentmap = self._get_parent_mapping(file)
                filetitle = self._get_file_name(file)
                orig = os.path.basename(file['path'])
                if filetitle != orig:
                    self.project.log("exception", "Normalized '{}' to '{}'".format(orig, filetitle), "warning", True)

                if 'bytes' in file:
                    self.file_size_bytes += int(file['bytes'])

                save_metadata_path = Common.assert_path(os.path.normpath(os.path.join(os.path.join(self.project.project_folders['metadata'], parentmap), filetitle + ".json")), self.project)
                if save_metadata_path:
                    self.project.log("transaction", "Queueing {} for download...".format(orig), "info", True)
                    d.put(Downloader.DownloadSlip(metadata_download_uri, file, save_metadata_path, 'path'))

                if self.project.args.mode == "full":
                    save_download_path = Common.assert_path(os.path.normpath(os.path.join(os.path.join(self.project.project_folders['data'], parentmap), filetitle)), self.project)
                    if save_download_path:
                        self.project.log("transaction", "Queueing {} for download...".format(orig), "info", True)
                        d.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'path'))

        self.project.log("transaction", "Total size of files to be acquired is {}".format(Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)
        if self.project.args.prompt:
            IO.get("Press ENTER to begin acquisition...")

        d.start()
        d.wait_for_complete()
        d2 = datetime.now()
        delt = d2 - d1

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
