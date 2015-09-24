import urllib
from urllib import parse
import urllib.request
from urllib import error
import time
import os
import sys
import datetime


def assert_path(p, project):
    p = os.path.abspath(p)
    p2 = safe_path(p)
    if not p2:
        project.log("exception", "ERROR '" + p + "' is too long a path for this operating system - Could NOT save file.", "critical", True)
        return None
    else:
        if p2 != p:
            project.log("exception", "Normalized '" + p + "' to '" + p2 + "'", "warning", True)
    return p2

def timely_filename(base, extension):
    d = datetime.datetime.now()
    s = "{base}_{year}-{month}-{day}-_{hour}-{minute}-{second}{ext}".format(base=base,year=d.year,month=d.month,day=d.day,hour=d.hour,minute=d.minute,second=d.second,ext=extension)
    return s

def safe_file_name(f):
    ret = f
    if ret == '..':
        ret = '__'

    posix = ['/', '\x00', '"']
    osx = ['/', '\x00', ':', '"']
    windows = ['*', '|', '\\', '/', ':', '<', '>', '?', '"']
    blacklist = []
    if sys.platform == "win32":
        blacklist = windows
    if sys.platform == "darwin":
        blacklist = osx
    if sys.platform == "linux2":
        blacklist = posix

    for c in blacklist:
        ret = ret.replace(c, '_')

    while ret.endswith("."):
        ret = ret[:-1]

    if len(ret) > 255:
        ext = ret[-4:]
        ret = ret[:246] + ext

    return ret


def safe_path(p):
    if sys.platform == "win32":
        p = path_normalization(p)
        if len(p) > 255:
            return None
    return p


def hashstring(str, hasher):
    hasher.update(str)
    return hasher.hexdigest()

def hashfile(file, hasher, blocksize=65536):
    buf = file.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = file.read(blocksize)
    return hasher.hexdigest()


def safefilename(f):
    f = f.replace('\\', '_')
    f = f.replace('/', '_')
    f = f.replace('..', '_')
    if len(f) > 260:
        f = f[:240] + '_'
    return f


def check_for_pause(project):
    while project.pause_signal:
        time.sleep(1)


def path_strip(p):
    p = p.replace(" " + os.sep, os.sep)
    p = p.replace(os.sep + " ", os.sep)
    return p


def path_normalization(p):
    p = path_strip(p)
    if path_strip(p) != p:
        return path_normalization(p)
    return p.strip()

def pause_project(p):
    p.pause_signal = 1
    print(os.linesep)


def webrequest(url, headers, http_intercept, data=None, binary=False, return_req=False):
    try:
        headers['user-agent'] = "searchgiant forensic cli"
        if data is None:
            # GET
            req = urllib.request.Request(url, None, headers)
            response = urllib.request.urlopen(req)
            if return_req:
                return response
            if binary:
                return response.read()
            return response.read().decode('utf-8')
        else:
            # POST
            req = urllib.request.Request(url, data.encode('utf-8'), headers)
            response = urllib.request.urlopen(req)
            if return_req:
                return response
            if binary:
                return response.read()
            return response.read().decode('utf-8')

    except urllib.error.HTTPError as err:
        new_headers = http_intercept(err)
        if new_headers:
            return webrequest(url, new_headers, http_intercept, data, binary, return_req)
        else:
            raise

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "{:.2f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.2f}{}{}".format(num, 'Yi', suffix)

def joinurl(b, p):
    if not b.endswith("/"):
        return urllib.parse.urljoin(b + "/", p)
    else:
        return urllib.parse.urljoin(b, p)


def dialog_result(response, default=True):
    if not response:
        return default
    if not type(response) is str:
        return default
    response = response.lower()
    if response[0] == "y":
        return True
    if response[0] == "n":
        return False



class Eastern(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(hours=-5)

    def tzname(self, dt):
        return "EST"

    def dst(self, dt):
        return datetime.timedelta(0)


class Universal(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(hours=0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


def getdate_withtz(tzclass):
    d = datetime.datetime.utcnow()
    d = d.replace(tzinfo=tzclass)
    return d

def utc_get_date_as_string():
    UTC = Universal()
    d = getdate_withtz(UTC)
    return d.strftime("(%Z) %Y-%m-%d")

def utc_get_datetime_as_string():
    UTC = Universal()
    d = getdate_withtz(UTC)
    return d.strftime("(%Z) %Y-%m-%d %H:%M:%S")



