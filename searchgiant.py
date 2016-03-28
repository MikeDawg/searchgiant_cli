#!/usr/bin/env python
__author__ = 'aurcioli'

import sys
import traceback
import os
import argparse
import threading
import time
import urllib.error
import http.client

from project import Project
from oi import IO
from common import Common

if __name__ == '__main__':
    # original_sigint = signal.getsignal(signal.SIGINT)
    # signal.signal(signal.SIGINT, exit_program)
    parser = argparse.ArgumentParser(description="Cloud Service forensic imaging tool")
    parser.add_argument('project_dir', metavar='project_dir', type=str,
                        help="Path where project will be created. If project already exists it will use existing settings")
    parser.add_argument('service', metavar='service_type', type=str,
                        help="Accepted values: google_drive, dropbox, gmail")
    parser.add_argument('--mode', '-m', metavar='mode', type=str,
                        help="Synchronization mode. Accepted values are: full, metadata. Default value is: full",
                        required=False, default="full")
    parser.add_argument('--threads', '-t', metavar='threads', type=int,
                        help="Amount of parallel threads used to download files", default=5)
    parser.add_argument('--prompt', '-p', help="Prompt before actually downloading anything", action="store_true")

    args = parser.parse_args()

    IO.IO.print_logo()

    P = Project.Project(args)
    try:
        P.start()
    except KeyboardInterrupt:
        P.pause_signal = 1
        print(os.linesep)
        IO.IO.put("Ctrl+C or other interrupt caught.", "critical")
        shutdown = IO.IO.get("Are you sure you want to cancel? [Y/n]")
        result = Common.dialog_result(shutdown)
        if result:
            P.pause_signal = 0
            P.shutdown_signal = 1
            while threading.active_count() > 1:
                for t in threading.enumerate():
                    IO.IO.put("Active: {}".format(t.name))
                IO.IO.put("Waiting for all threads to shutdown gracefully...({} remaining)".format(threading.active_count()), "warning")
                time.sleep(3)
        else:
            P.pause_signal = 0

    except urllib.error.HTTPError as err:
        P.log("exception", "HTTP ERROR {} - Response from server:\n{}".format(err.code, err.read().decode('utf-8')), "critical", True)
        sys.exit(1)
    except http.client.IncompleteRead:
        P.log("exception", "HTTP Incomplete Read - Please restart acquisition", "critical", True)
        sys.exit(1)
    except Exception as err:
        print(str(err), sys.stderr)
        traceback.print_stack(f=sys.stderr)


