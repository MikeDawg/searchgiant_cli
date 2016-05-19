import json
from datetime import datetime
import os
import hashlib
import urllib
from onlinestorage import OnlineStorage
from common import Common
from downloader import Downloader
from oi.IO import IO
from oauth2providers import OAuth2Providers


class GoogleDrive(OnlineStorage.OnlineStorage):
    files = []
    verification = []

    oauth = {"access_token": "",
             "refresh_token": "",
             "expires_in:": 0}

    def __init__(self, project):
        self.project = project
        self.oauth_provider = OAuth2Providers.OAuth2Provider(self,"google", "refresh_token")
        self.project.save("API_ENDPOINT", 'https://www.googleapis.com/drive/v2')
        self.project.save("OAUTH_SCOPE", 'https://www.googleapis.com/auth/drive.readonly')
        self.files = []
        self.file_size_bytes = 0
        super(GoogleDrive, self).__init__(self, project.name)

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
                   "lastModifyingUserName,writersCanShare,sharedWithMeDate,sharingUser,sharingUserEmail,ownerNames{}\n")

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
            f.write(rowStr + '\n')

        f.close()

    def verify(self):
        self.project.log("transaction", "Verifying all downloaded files...", "highlight", True)
        verification_file = os.path.join(self.project.working_dir, Common.timely_filename("verification", ".csv"))
        errors = 0
        pct = 0
        tot_hashes = 0
        with open(verification_file, 'w') as f:
            f.write("TIME_PROCESSED,REMOTE_FILE,LOCAL_FILE,REMOTE_HASH,LOCAL_HASH,MATCH\n")
            for item in self.verification:
                lf = item['local_file']
                rf = item['remote_file']
                rh = ""
                lh = ""
                match = ""
                lf_exists = os.path.isfile(lf)
                if lf_exists and 'remote_hash' in item:
                    lh = Common.hashfile(open(lf, 'rb'), hashlib.md5())
                    tot_hashes += 1
                    rh = item['remote_hash']
                    if lh == item['remote_hash']:
                        match = "YES"
                    else:
                        match = "NO"
                        errors += 1
                        self.project.log("exception", "Verification failed for remote file {} and local file {}".format(rf,lf), "critical", True)
                # elif lf_exists and 'fileSize' in item:
                #     tot_hashes = tot_hashes + 1
                #     remote_bytes = item['fileSize']
                #     local_bytes = os.path.getsize(lf)
                #     rh = "{} bytes".format(remote_bytes)
                #     lh = "{} bytes".format(local_bytes)
                #     if remote_bytes == local_bytes:
                #         match = "YES"
                #     else:
                #         match = "NO"
                #         errors += 1
                #         self.project.log("exception",
                #                          "Verification failed for remote file {} and local file {}".format(rf, lf),
                #                          "critical", True)
                else:
                    rh = "(Remote hash unavailable)" if lf_exists else "(Local file not found)"
                    if not lf_exists: errors = errors + 1
                    match = "N/A"
                f.write('"{date}","{rf}","{lf}","{rh}","{lh}","{m}"\n'.format(date=Common.utc_get_datetime_as_string(),rf=rf,lf=lf,rh=rh,lh=lh,m=match))
        pct = ((tot_hashes - errors) / tot_hashes) * 100
        self.project.log("transaction", "Verification of {} hashes completed with {} errors. ({:.2f}% Success rate)".format(tot_hashes, errors, pct), "highlight", True)

    def sync(self):
        d1 = datetime.now()
        self.filecount = 0
        self.content_downloader = Downloader.Downloader

        if self.project.args.mode == "full":
            self.project.log("transaction", "Full acquisition initiated", "info", True)
            self.content_downloader = Downloader.Downloader(self.project, self.oauth_provider.http_intercept, self._save_file, self.oauth_provider.get_auth_header,
                                  self.project.threads)
        else:
            self.project.log("transaction", "Metadata acquisition initiated", "info", True)

        self.content_downloader.start()
        self.initialize_items()
        # cnt = len(self.files)
        # self.project.log("transaction", "Total items queued for acquisition: " + str(cnt), "info", True)
        self.metadata()

        # trash_folder = os.path.join(self.project.acquisition_dir, "trash")
        # trash_metadata_folder = os.path.join(self.project.acquisition_dir, "trash_metadata")

        #for file in self.files:
            # self.project.log("transaction", "Calculating " + file['title'], "info", True)
            # download_uri = self._get_download_url(file)
            # parentmap = self._get_parent_mapping(file, self.files)
            #
            # filetitle = self._get_file_name(file)
            # if filetitle != file['title']:
            #         self.project.log("exception", "Normalized '" + file['title'] + "' to '" + filetitle + "'", "warning",
            #                          True)
            #
            # if file['labels']['trashed'] == True:
            #     save_download_path = os.path.join(trash_folder, parentmap)
            #     save_metadata_path = os.path.join(trash_metadata_folder, parentmap)
            #     save_download_path = os.path.normpath(os.path.join(save_download_path, filetitle))
            #     save_metadata_path = os.path.normpath(os.path.join(save_metadata_path, filetitle + '.json'))
            # else:
            #     save_download_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["data"], parentmap), filetitle))
            #     save_metadata_path = os.path.normpath(os.path.join(os.path.join(self.project.project_folders["metadata"], parentmap), filetitle + ".json"))
            #
            # save_download_path = Common.assert_path(save_download_path, self.project)
            # save_metadata_path = Common.assert_path(save_metadata_path, self.project)
            #
            # if self.project.args.mode == "full":
            #     if save_download_path:
            #         v = {"remote_file": os.path.join(parentmap, file['title']),
            #              "local_file": save_download_path}
            #
            #         download_file = True
            #         if 'md5Checksum' in file:
            #             v['remote_hash'] = file['md5Checksum']
            #
            #         if os.path.isfile(save_download_path):
            #             if 'md5Checksum' in file:
            #                 file_hash = Common.hashfile(open(save_download_path, 'rb'), hashlib.md5())
            #                 if file_hash == file['md5Checksum']:
            #                     download_file = False
            #                     self.project.log("exception", "Local and remote hash matches for " + file[
            #                         'title'] + " ... Skipping download", "warning", True)
            #                 else:
            #                     self.project.log("exception", "Local and remote hash differs for " + file[
            #                         'title'] + " ... Queuing for download", "critical", True)
            #
            #
            #             else:
            #                 self.project.log("exception", "No hash information for file ' " + file['title'] + "'", "warning", True)
            #
            #         if download_file and download_uri:
            #             self.project.log("transaction", "Queueing " + file['title'] + " for download...", "info", True)
            #             content_downloader.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'title'))
            #             if 'fileSize' in file:
            #                 self.file_size_bytes += int(file['fileSize'])
            #
            #         # If it's a file we can add it to verification file
            #         if download_uri:
            #             self.verification.append(v)
            #
            # if save_metadata_path:
            #     self._save_file(json.dumps(file, sort_keys=True, indent=4), Downloader.DownloadSlip(download_uri, file, save_metadata_path, 'title'), False)

        self.content_downloader.finished_queuing = True

        self.content_downloader.wait_for_complete()
        d2 = datetime.now()
        delt = d2 - d1
        self.project.log("transaction", "Acquired {} files for a total size of {}".format(self.filecount, Common.sizeof_fmt(self.file_size_bytes, "B")), "highlight", True)
        self.verify()
        Common.print_failures(self.project, [self.content_downloader])
        self.project.log("transaction", "Acquisition completed in {}".format(str(delt)), "highlight", True)

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
        if file['mimeType'] == "application/vnd.google-apps.folder" or \
           file['mimeType'] == "application/vnd.google-apps.form" or \
           file['mimeType'] == "application/vnd.google-apps.fusiontable":
            return None
        else:
            dl = Common.joinurl(self.project.config['API_ENDPOINT'], "files/{fileid}?alt=media".format(fileid=file['id']))
            return dl

    # def get_auth_header(self):
    #     return {'Authorization': 'Bearer ' + self.oauth['access_token']}

    def _build_fs(self, link):
        self.project.log("transaction", "Calculating total drive items...", "info", True)
        response = self.get_response(link)
        if response:
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
            self.process_file(i)
            if self.project.args.include_revisions:
                revisions = self.get_revisions(i)
                for rev in revisions:
                    self.process_file(rev)

    def process_file(self, file):
        self.project.log("transaction", "Calculating " + file['title'], "info", True)
        download_uri = self._get_download_url(file)
        parentmap = self._get_parent_mapping(file, self.files)

        filetitle = self._get_file_name(file)
        if filetitle != file['title']:
            self.project.log("exception", "Normalized '" + file['title'] + "' to '" + filetitle + "'", "warning",
                             True)

        trash_folder = os.path.join(self.project.acquisition_dir, "trash")
        trash_metadata_folder = os.path.join(self.project.acquisition_dir, "trash_metadata")
        save_download_path = self.project.project_folders["data"]
        save_metadata_path = self.project.project_folders["metadata"]

        if file['labels']['trashed'] == True:
            save_download_path = os.path.join(trash_folder, parentmap)
            save_metadata_path = os.path.join(trash_metadata_folder, parentmap)
            # save_download_path = os.path.normpath(os.path.join(save_download_path, filetitle))
            # save_metadata_path = os.path.normpath(os.path.join(save_metadata_path, filetitle + '.json'))
        if file['kind'] == "drive#revision":
            original_title = Common.safe_file_name(file['SG_ORIGINAL_TITLE'])
            save_download_path = os.path.join(save_download_path, os.path.splitext(original_title)[0] + "_revisions")
            save_metadata_path = os.path.join(save_metadata_path, os.path.splitext(original_title)[0] + "_revisions")

        save_download_path = os.path.normpath(os.path.join(save_download_path, filetitle))
        save_metadata_path = os.path.normpath(os.path.join(save_metadata_path, filetitle + '.json'))

        save_download_path = Common.assert_path(save_download_path, self.project)
        save_metadata_path = Common.assert_path(save_metadata_path, self.project)

        # # else:
        # #     save_download_path = os.path.normpath(
        # #         os.path.join(os.path.join(self.project.project_folders["data"], parentmap), filetitle))
        # #     save_metadata_path = os.path.normpath(
        # #         os.path.join(os.path.join(self.project.project_folders["metadata"], parentmap), filetitle + ".json"))
        #
        # if file['kind'] == "drive#revision":
        #     save_download_path = os.path.normpath(os.path.join(save_download_path))


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


                    else:
                        self.project.log("exception", "No hash information for file ' " + file['title'] + "'",
                                         "warning", True)

                if download_file and download_uri:
                    self.project.log("transaction", "Queueing " + file['title'] + " for download...", "info", True)
                    self.content_downloader.put(Downloader.DownloadSlip(download_uri, file, save_download_path, 'title'))
                    self.filecount += 1
                    #@TODO FILESIZE IS FUCKED UP
                    if 'fileSize' in file:
                        self.file_size_bytes += int(file['fileSize'])

                # If it's a file we can add it to verification file
                if download_uri:
                    self.verification.append(v)

        if save_metadata_path:
            self._save_file(json.dumps(file, sort_keys=True, indent=4),
                            Downloader.DownloadSlip(download_uri, file, save_metadata_path, 'title'), False)

    def get_revisions(self, item):
        self.project.log("transaction", "Fetching revisions for {}".format(item['title']), "info", True)
        link = Common.joinurl(self.project.config['API_ENDPOINT'], "files/{}/revisions".format(item['id']))
        response = self.get_response(link)
        revs = []
        if response:
            json_response = json.loads(response)
            for revision in json_response['items']:
                filename_split = os.path.splitext(item['title'])
                filename_no_ext = filename_split[0]
                revision['title'] = "{}_rev_{}{}".format(filename_no_ext, revision['id'], filename_split[1])
                revision['parents'] = item['parents']
                revision['labels'] = item['labels']
                revision['SG_ORIGINAL_TITLE'] = item['title']
                revs.append(revision)
        return revs

    def get_response(self, link):
        try:
            response = Common.webrequest(link, self.oauth_provider.get_auth_header(),
                                         self.oauth_provider.http_intercept)
            return response
        except urllib.error.HTTPError as err:
            self.project.log("exception",
                             "{} failed to download - HTTPError {}".format(link, err.code),
                             "error", True)







