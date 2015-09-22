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

# TODO: Produce verification log of all files and hashes as files are being downloaded


class GoogleDrive(OnlineStorage.OnlineStorage):
    files = []
    verification = []

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
        self._build_fs(Common.joinurl(self.project.config['API_ENDPOINT'], "files?maxResults=0"))

    def metadata(self):
        self.project.log("transaction", "Generating metadata CSV File...", "info", True)
        if not self.files:
            self.initialize_items()

        fname = Common.timely_filename("FileList", ".csv")
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

    def verify(self):
        self.project.log("transaction", "Verifying all downloaded files...", "highlight", True)
        verification_file = os.path.join(self.project.working_dir, Common.timely_filename("verification", ".csv"))
        errors = 0
        pct = 0
        tot_hashes = 0
        with open(verification_file, 'w') as f:
            f.write("TIME_PROCESSED,REMOTE_FILE,LOCAL_FILE,REMOTE_HASH,LOCAL_HASH,MATCH\r\n")
            for item in self.verification:
                rh = ""
                match = ""
                lh = Common.hashfile(open(item['local_file'], 'rb'), hashlib.md5())
                lf = item['local_file']
                rf = item['remote_file']
                if 'remote_hash' in item:
                    tot_hashes += 1
                    rh = item['remote_hash']
                    if lh == item['remote_hash']:
                        match = "YES"
                    else:
                        match = "NO"
                        errors += 1
                        self.project.log("exception", "Verification failed for remote file {} and local file {}".format(rf,lf), "critical", True)
                else:
                    rh = "NONE PROVIDED"
                    match = "N/A"
                d = datetime.now()
                f.write('"{date}","{rf}","{lf}","{rh}","{lh}","{m}"\r\n'.format(date=str(d),rf=rf,lf=lf,rh=rh,lh=lh,m=match))
        pct = ((tot_hashes - errors) / tot_hashes) * 100
        self.project.log("transaction", "Verification of {} items completed with {} errors. ({:.2f}% Success rate)".format(tot_hashes, errors, pct), "highlight", True)

    def sync(self):
        d1 = datetime.now()
        d = Downloader.Downloader
        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
            d = Downloader.Downloader(self.project, self.http_intercept, self._save_file, self.get_auth_header,
                                  self.project.threads)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)

        self.initialize_items()
        cnt = len(self.files)
        self.project.log("transaction", "Total items queued for acquisition: " + str(cnt), "info", True)
        self.metadata()

        for file in self.files:
            self.project.log("transaction", "Calculating " + file['title'], "info", True)
            download_uri = self._get_download_url(file)
            parentmap = self._get_parent_mapping(file, self.files)

            filetitle = self._get_file_name(file)
            if filetitle != file['title']:
                    self.project.log("exception", "Normalized '" + file['title'] + "' to '" + filetitle + "'", "warning",
                                     True)

            if file['labels']['trashed'] == True:
                save_download_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["trash"], parentmap), filetitle))
                save_metadata_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["trash_metadata"], parentmap), filetitle + ".json"))
            else:
                save_download_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["data"], parentmap), filetitle))
                save_metadata_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["metadata"], parentmap), filetitle + ".json"))

            save_download_path = Common.assert_path(save_download_path, self.project)
            save_metadata_path = Common.assert_path(save_metadata_path, self.project)

            if self.project.args.mode == "full":
                if save_download_path:
                    v = {"remote_file": os.path.join(parentmap, file['title']),
                         "local_file": save_download_path}

                    download_file = True
                    if 'md5Checksum' in file:
                        v['remote_hash'] = file['md5Checksum']

                    if os.path.isfile(save_download_path):
                        if 'md5Checksum' in file:
                            file_hash = Common.hashfile(open(save_download_path, 'rb'), hashlib.md5())
                            if file_hash == file['md5Checksum']:
                                download_file = False
                                self.project.log("exception", "Local and remote hash matches for " + file[
                                    'title'] + " ... Skipping download", "warning", True)
                            else:
                                self.project.log("exception", "Local and remote hash differs for " + file[
                                    'title'] + " ... Queuing for download", "critical", True)

                                # # # TODO : DEBUG - This is how I caught all edge cases regarding multiple versioned files
                                #     TODO: And other google drive oddities
                                # print("FileHash=" + file_hash)
                                # print("Remote=" + file['md5Checksum'])
                                # print("ParentMapping=" + parentmap)
                                # print("DLPath=" + save_download_path)
                                # input()

                        else:
                            self.project.log("exception", "No hash information for file ' " + file['title'] + "'", "warning", True)

                    if download_file and download_uri:
                        self.project.log("transaction", "Queueing " + file['title'] + " for download...", "info", True)
                        d.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'title'))
                        if 'fileSize' in file:
                            self.file_size_bytes += int(file['fileSize'])

                    # If it's a file we can add it to verification file
                    if download_uri:
                        self.verification.append(v)

            if save_metadata_path:
                self._save_file(json.dumps(file, sort_keys=True, indent=4), Downloader.DownloadSlip(download_uri, file, save_metadata_path, 'title'))

        self.project.log("transaction", "Total size of files to be acquired is {}".format(
            Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)

        if self.project.args.prompt:
            IO.get("Press ENTER to begin acquisition...")

        d.start()
        d.wait_for_complete()
        d2 = datetime.now()
        delt = d2 - d1
        self.verify()
        self.project.log("transaction", "Acquisition completed in {}".format(str(delt)), "highlight", True)

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

    def is_duplicate(self, file):
        for item in self.files:
            if item['title'] == file['title']:
                if file['version'] != item['version']:
                    if self._get_parent_mapping(file, self.files) == self._get_parent_mapping(item, self.files):
                        return True
        return False

    def _get_file_name(self, file):
        mime_type = file['mimeType']
        title = file['title']
        version = ""
        drivetype = ""
        ext = ""
        if self.is_duplicate(file):
            version = ' (' + file['version'] + ')'

        if ('application/vnd.google-apps' in mime_type) and (mime_type != "application/vnd.google-apps.folder"):
            if 'exportLinks' in file:
                export_link = self._get_download_url(file)
                ext = '.' + export_link[export_link.index('exportFormat=') + 13:]
                drivetype = mime_type[mime_type.rindex('.'):]

        if '.' in title:
            extension = title[title.rindex('.'):]
            base = title[:title.rindex('.')]
            filename = "{base}{extension}{drivetype}{ext}".format(base=base, extension=extension, drivetype=drivetype, ext=ext)
        else:
            filename = "{title}{drivetype}{ext}".format(title=title,drivetype=drivetype, ext=ext)

        if '.' in filename:
            extension = filename[filename.rindex('.'):]
            base = filename[:filename.rindex('.')]
            filename = "{base}{version}{extension}".format(base=base, version=version, extension=extension)
        else:
            filename = "{title}{version}".format(title=title, version=version)
        return Common.safe_file_name(filename)

    def _get_download_url(self, file):
        if 'downloadUrl' in file:
            return file['downloadUrl']
        if 'exportLinks' in file:
            order = []
            # The following logic makes the program functionality predictable
            # Choose from a preferred list of mimetypes
            # Or else sort the list alphabetically and choose the first option
            # TODO: Find somewhere else to put this list
            if file['mimeType'] == "application/vnd.google-apps.document":
                order.append("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                order.append("application/vnd.oasis.opendocument.text")
                order.append("application/pdf")
                order.append("application/rtf")
                order.append("text/plain")
                order.append("text/html")
            elif file['mimeType'] == "application/vnd.google-apps.spreadsheet":
                order.append("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                order.append("application/x-vnd.oasis.opendocument.spreadsheet")
                order.append("text/csv")
                order.append("application/pdf")
            elif file['mimeType'] == "application/vnd.google-apps.drawing":
                order.append("image/png")
                order.append("image/jpeg")
                order.append("image/svg+xml")
                order.append("application/pdf")
            elif file['mimeType'] == "application/vnd.google-apps.presentation":
                order.append("application/vnd.openxmlformats-officedocument.presentationml.presentation")
                order.append("application/pdf")
                order.append("text/plain")
            else:
                order = None

            if order:
                for mtype in order:
                    if mtype in file['exportLinks']:
                        return file['exportLinks'][mtype]

            for key, value in sorted(file['exportLinks'].items()):
                return file['exportLinks'][key]

        if "file" in file:
            return file[0]
        if file['mimeType'] == "application/vnd.google-apps.folder":
            return None
        else:
            dl = Common.joinurl(self.project.config['API_ENDPOINT'], "files/{fileid}?alt=media".format(fileid=file['id']))
            return dl

    def get_auth_header(self):
        return {'Authorization': 'Bearer ' + self.oauth['access_token']}

    def _build_fs(self, link):
        self.project.log("transaction", "Calculating total drive items...", "info", True)
        response = Common.webrequest(link, self.get_auth_header(), self.http_intercept)
        json_response = json.loads(response)

        if 'nextLink' in json_response:
            items = json_response['items']
            self._add_items_to_files(items)
            self._build_fs(json_response['nextLink'])
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
