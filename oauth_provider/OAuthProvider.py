__author__ = 'aurcioli'

class OAuthProvider():
    attributes = {}
    expired_token_code = 401
    project = None
    def __init__(self, project, expired_token_code):
        self.attributes = {'access_token': "",
                           'refresh_token': "",
                           'expires_in': 0}

        self.expired_token_code = expired_token_code
        self.project = project

    def intercept(self, err):
        if err.code == 401:
            self.authorize()

    def authorize(self):
        pass



