import re
import socket

import requests

from common.colors import W, bad, end, good
from common.uriParser import parsing_url as hostd


class GatherHost:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers

    def match_info(self, regex, data):
        match = re.search(regex, data)
        if match:
            return dict(data=match.group(1))

    def match_printer(self, to_match, match):
        if match["data"]:
            print(" {0} {1} : {2}".format(good, to_match, match["data"]))

    def os_server(self):
        response = requests.get(self.url, headers=self.headers, verify=False).headers
        try:
            regx = re.compile(r"(.+) \((.+)\)")
            data = regx.search(response["server"])
            try:
                print(" {0} {1}Server :{2} {3}".format(good, W, end, data.group(1)))
                print(" {0} {1}OS :{2} {3}".format(good, W, end, data.group(2)))
            except AttributeError:
                print(" {0} Cannot Find OS & HostingServer ".format(bad))
        except KeyError:
            print(" {0} Cannot Find the server headers ".format(bad))

    def web_host(self):
        try:
            ip = socket.gethostbyname(hostd(self.url))
            print(" {0} CloudFlare IP : {1}".format(good, ip))
            ipinfo = "http://ipinfo.io/" + ip + "/json"
            gather = requests.get(ipinfo, self.headers).text

            self.match_printer(
                "Hostname", self.match_info(r"hostname\": \"(.+?)\"", gather)
            )
            self.match_printer("City", self.match_info(r"city\": \"(.+?)\"", gather))
            self.match_printer(
                "Region", self.match_info(r"region\": \"(.+?)\"", gather)
            )
            self.match_printer(
                "Country", self.match_info(r"country\": \"(.+?)\"", gather)
            )
            self.match_printer(
                "Timezone", self.match_info(r"timezone\": \"(.+?)\"", gather)
            )
            self.match_printer("Org", self.match_info(r"org\": \"(.+?)\"", gather))
            self.match_printer("Location", self.match_info(r"loc\": \"(.+?)\"", gather))
        except Exception as err:
            print(" {0} Parse Error : {1}".format(bad, err))
