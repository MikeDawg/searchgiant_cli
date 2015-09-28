from common import Common
import os

class OnlineStorage:
    api_endpoint = ""
    name = ""

    def __init__(self, app, name):
        self.project = app.project
        self.name = name

    def _save_file(self, data, slip, stream=True):
        Common.check_for_pause(self.project)
        savepath = slip.savepath

        path_to_create = os.path.dirname(savepath)  # Just the directory not the filename
        if not os.path.isdir(path_to_create):
            os.makedirs(path_to_create, exist_ok=True)

        self.project.savedata(data, savepath, stream)
        self.project.log("transaction", "Saved file to " + savepath, "info", True)
