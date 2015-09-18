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
        self.project.log("transaction", "Initiating OAUTH 2 Protocol with " + self.project.config['TOKEN_ENDPOINT'],
                         "info", True)
        if not self.oauth['refresh_token']:
            self.project.log("transaction", "No valid refresh token found..", "warning", True)
            if not self.project.config['CLIENT_ID'] or not self.project.config['CLIENT_SECRET']:
                self.project.log("transaction", "No client id or client secret. Asking for user input..", "warning",
                                 True)
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
                self.project.log("transaction",
                                 "Received client_id and client_secret from user (" + client_id + ") (" + client_id + ")",
                                 "info", True)

            # Step 1
            response_type = 'code'
            query_string = (
                {'redirect_uri': self.project.config['REDIRECT_URI'], 'response_type': response_type,
                 'client_id': self.project.config['CLIENT_ID'],
                 'scope': self.project.config['OAUTH_SCOPE'], 'approval_prompt': 'force', 'access_type': 'offline'})
            params = urllib.parse.urlencode(query_string)
            step1 = self.project.config['OAUTH_ENDPOINT'] + '?' + params
            try:
                webbrowser.open(step1)
            except:
                IO.put("Error launching webbrowser to receive authorization code. You must manually visit the following url and enter the code at this page: \n{}".format(step1),"highlight")
            code = IO.get("Authorization Code:")
            self.project.log("transaction", "Auth code received: (" + code + ")", "info", True)
            # Step 2
            query_string = ({'code': code, 'redirect_uri': self.project.config['REDIRECT_URI'],
                             'client_id': self.project.config['CLIENT_ID'], 'scope': '',
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

    def initialize_items(self):
        self.files = []
        self.project.log("transaction", "API Endpoint is " + self.project.config['API_ENDPOINT'], "info", True)
        self._get_items(Common.joinurl(self.project.config['API_ENDPOINT'], "files?maxResults=0"))


    def metadata(self):
        self.project.log("transaction", "Generating metadata CSV File...", "info", True)
        if not self.files:
            self.initialize_items()

        d = datetime.now()
        fname = "FileList_{year}_{month}_{day}_{hour}_{minute}.csv".format(year=d.year, month=d.month, day=d.day,
                                                                           hour=d.hour, minute=d.minute)
        metadata_file = os.path.join(self.project.working_dir, fname)
        IO.put("Writing CSV File '{}'".format(metadata_file))

        f = open(metadata_file, "w")

        columns = ("id,title,fileExtension,fileSize,createdDate,modifiedDate,modifiedByMeDate,md5Checksum,"
                   "kind,version,parents,restricted,hidden,trashed,starred,viewed,markedViewedByMeDate,lastViewedByMeDate,"
                   "lastModifyingUserName,writersCanShare,sharedWithMeDate,sharingUser,sharingUserEmail,ownerNames\n")

        f.write(columns)
        for i in self.files:
            row2 = []
            # Data normalization
            row2.append('None' if 'id' not in i else repr(i['id']))
            row2.append('None' if 'title' not in i else '"' + i['title'] + '"')
            row2.append('None' if 'fileExtension' not in i else repr(i['fileExtension']))
            row2.append('None' if 'fileSize' not in i else i['fileSize'])
            row2.append('None' if 'createdDate' not in i else i['createdDate'])
            row2.append('None' if 'modifiedDate' not in i else i['modifiedDate'])
            row2.append('None' if 'modifiedByMeDate' not in i else i['modifiedByMeDate'])
            row2.append('None' if 'md5Checksum' not in i else '"' + i['md5Checksum'] + '"')
            row2.append('None' if 'kind' not in i else repr(i['kind']))
            row2.append('None' if 'version' not in i else i['version'])
            if 'parents' not in i or len(i['parents']) == 0:
                row2.append('None')
            else:
                parStr = '"'
                for p in i['parents']:
                    parStr = parStr + str(p['id']) + ','
                parStr = parStr[:len(parStr) - 1]
                parStr = parStr + '"'
                row2.append(parStr)

            row2.append('None' if 'labels' not in i else repr(i['labels']['restricted']))
            row2.append('None' if 'labels' not in i else repr(i['labels']['hidden']))
            row2.append('None' if 'labels' not in i else repr(i['labels']['trashed']))
            row2.append('None' if 'labels' not in i else repr(i['labels']['starred']))
            row2.append('None' if 'labels' not in i else repr(i['labels']['viewed']))
            row2.append('None' if 'markedViewedByMeDate' not in i else i['markedViewedByMeDate'])
            row2.append('None' if 'lastViewedByMeDate' not in i else i['lastViewedByMeDate'])
            row2.append('None' if 'lastModifyingUserName' not in i else '"' + i['lastModifyingUserName'] + '"')
            row2.append('None' if 'writersCanShare' not in i else i['writersCanShare'])
            row2.append('None' if 'sharedWithMeDate' not in i else i['sharedWithMeDate'])
            row2.append('None' if 'sharingUser' not in i else '"' + i['sharingUser']['displayName'] + '"')
            row2.append('None' if 'sharingUser' not in i else '"' + i['sharingUser']['emailAddress'] + '"')
            if 'ownerNames' not in i or len(i['ownerNames']) == 0:
                row2.append('None')
            else:
                ownStr = '"'
                for o in i['ownerNames']:
                    ownStr = ownStr + str(o) + ','
                ownStr = ownStr[:len(ownStr) - 1]
                ownStr = ownStr + '"'
                row2.append(ownStr)

            rowStr = ""
            for r in row2:
                rowStr = rowStr + str(r) + ","
            rowStr = rowStr[:len(rowStr) - 1]
            f.write(rowStr + "\n")
            #columns = columns + rowStr + "\n"
        f.close()


    def assert_path(self, p):
        p = os.path.abspath(p)
        p2 = Common.safe_path(p)
        if not p2:
            self.project.log("exception", "ERROR '" + p + "' is too long a path for this operating system", "critical", True)
            return None
        else:
            if p2 != p:
                self.project.log("exception", "Normalized '" + p + "' to '" + p2 + "'",
                                     "warning", True)
            return p2


    def sync(self):
        d1 = datetime.now()
        d = Downloader.Downloader
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full synchronization initiated", "info", True)
            d = Downloader.Downloader(self.project, self.http_intercept, self._save_file, self.get_auth_header,
                                  self.project.threads)
        else:
            self.project.log("transaction", "Metadata synchronization initiated", "info", True)

        self.initialize_items()
        cnt = len(self.files)
        self.project.log("transaction", "Total files queued for synchronization: " + str(cnt), "info", True)
        self.metadata()

        for file in self.files:
            self.project.log("transaction", "Calculating " + file['title'], "info", True)
            download_uri = self._get_download_url(file)
            parentmap = self._get_parent_mapping(file, self.files)

            filetitle = Common.safe_file_name(file['title'])
            if filetitle != file['title']:
                    self.project.log("exception", "Normalized '" + file['title'] + "' to '" + filetitle + "'", "warning",
                                     True)
            save_download_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["data"], parentmap), filetitle))
            save_metadata_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["metadata"], parentmap), filetitle + ".json"))

            save_download_path = self.assert_path(save_download_path)
            save_metadata_path = self.assert_path(save_metadata_path)

            if self.project.args.mode == "full":
                download_file = True
                if save_download_path:
                    if os.path.isfile(save_download_path):
                        if 'md5Checksum' in file:
                            if Common.hashfile(open(save_download_path, 'rb'), hashlib.md5()) == file['md5Checksum']:
                                download_file = False
                                self.project.log("exception", "Local and remote hash matches for " + file[
                                    'title'] + " ... Skipping download", "warning", True)
                            else:
                                self.project.log("exception", "Local and remote hash differs for " + file[
                                    'title'] + " ... Queuing for download", "critical", True)
                        else:
                            self.project.log("exception", "No hash information for file ' " + file['title'] + "'", "warning", True)
                            if 'fileSize' in file:
                                sz = os.stat(save_download_path)
                                if sz.st_size == int(file['fileSize']):
                                    self.project.log("exception", "Local and remote file are same size for {} ... Skipping download".format(file['title']), "warning", True)
                                    download_file = False
                                else:
                                    self.project.log("exception", "Local and remote file sizes are different for {} ... Queuing for download".format(file['title']), "critical", True)

                    if download_file and download_uri:
                        self.project.log("transaction", "Queueing " + file['title'] + " for download...", "info", True)
                        d.put(Downloader.DownloadSlip(download_uri, file, save_download_path))
                        if 'fileSize' in file:
                            self.file_size_bytes += int(file['fileSize'])

            if save_metadata_path:
                # We can't really use hashes here for metadata since some things like Thumbnail link can change on each request
                self._save_file(None, Downloader.DownloadSlip(download_uri, file, save_metadata_path))

        self.project.log("transaction", "Total size of files to be synchronized is {}".format(
            Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)

        if self.project.args.prompt:
            IO.get("Press ENTER to begin synchronization...")

        d.start()
        while not d.empty():
            time.sleep(1)
        d2 = datetime.now()
        delt = d2 - d1
        self.project.log("transaction","Synchronization completed in {}".format(str(delt)), "highlight", True)

    def _save_file(self, data, slip):
        Common.check_for_pause(self.project)
        savepath = slip.savepath
        file_item = slip.item
        path_to_create = os.path.dirname(savepath)  # Just the directory not the filename

        if not os.path.isdir(path_to_create):
            os.makedirs(path_to_create, exist_ok=True)
        if data:
            self.project.savedata(data, savepath)
            self.project.log("transaction", "Saved file to " + savepath, "info", True)
        else:
            self.project.log("transaction", "Saving metadata to " + savepath, "info", True)
            data = json.dumps(file_item, sort_keys=True, indent=4)
            self.project.savedata(data, savepath, False)

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
            self.project.log("exception", "Error and system does not know how to handle: " + str(err.code), "critical",
                             True)
