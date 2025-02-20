#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

from common.colors import W, B, Y, good, end, run, info
from modules.executor.Wordpress import Wordpress
from modules.executor.Magento import Magento
from modules.executor.Prestashop import Prestashop
from modules.executor.Lokomedia import Lokomedia
from modules.executor.Lokomedia2 import Lokomedia2
from modules.executor.Drupal import Drupal
from modules.executor.Joomla import Joomla
from modules.executor.Uknown import Uknown
from modules.executor.Opencart import Opencart

import re, requests, time


class CMS(object):
    def __init__(
        self,
        url,
        headers=None,
        exploit=False,
        domain=False,
        webinfo=False,
        serveros=False,
        cmsinfo=False,
        dnsdump=False,
        port=False,
    ):
        self.url = url
        self.headers = headers
        self.exploit = exploit
        self.domain = domain
        self.webinfo = webinfo
        self.serveros = serveros
        self.cmsinfo = cmsinfo
        self.dnsdump = dnsdump
        self.port = port

    def __getlmcontent__(self):
        lm_content = self.url + "/smiley/1.gif"
        return requests.get(lm_content, headers=self.headers, verify=False).text

    def __getlm2content__(self):
        lm2_content = self.url + "/rss.xml"
        return requests.get(lm2_content, headers=self.headers, verify=False).text

    def __getcontent__(self):
        return requests.get(self.url, headers=self.headers, verify=False).text

    def __getexploit__(self):
        if self.exploit:
            return True

    def __getdomain__(self):
        if self.domain:
            return True

    def __getwebinfo__(self):
        if self.webinfo:
            return True

    def __getserveros__(self):
        if self.serveros:
            return True

    def __getcmsinfo__(self):
        if self.cmsinfo:
            return True

    def __getdnsdump__(self):
        if self.dnsdump:
            return True

    def __getport__(self):
        if self.port:
            return self.port

    def detect(self):
        """
        this module to detect cms & return type of cms.
        & make instance of cms.
        """
        if re.search(
            re.compile(
                r"<script type=\"text/javascript\" src=\"/media/system/js/mootools.js\"></script>|/media/system/js/|com_content|Joomla!"
            ),
            self.__getcontent__(),
        ):
            name = "Joomla"
            return name

        elif re.search(
            re.compile(r"wp-content|wordpress|xmlrpc.php"), self.__getcontent__()
        ):
            name = "Wordpress"
            return name
        elif re.search(
            re.compile(r"Drupal|drupal|sites/all|drupal.org"), self.__getcontent__()
        ):
            name = "Drupal"
            return name

        elif re.search(re.compile(r"Prestashop|prestashop"), self.__getcontent__()):
            name = "Prestashop"
            return name
        elif re.search(
            re.compile(r"route=product|OpenCart|route=common|catalog/view/theme"),
            self.__getcontent__(),
        ):
            name = "Opencart"
            return name

        elif re.search(
            re.compile(
                r"Log into Magento Admin Page|name=\"dummy\" id=\"dummy\"|Magento"
            ),
            self.__getcontent__(),
        ):
            name = "Magento"
            return name
        elif re.search(re.compile(r"image/gif"), self.__getlmcontent__()):
            name = "Lokomedia1"
            return name

        elif re.search(re.compile(r"lokomedia"), self.__getlm2content__()):
            name = "Lokomedia2"
            return name
        else:
            name = "Uknown"
            return name

    def serialize(self):
        result = dict(
            name=self.detect(),
            exploit=self.__getexploit__(),
            domain=self.__getdomain__(),
            webinfo=self.__getwebinfo__(),
            serveros=self.__getserveros__(),
            cmsinfo=self.__getcmsinfo__(),
            dnsdump=self.__getdnsdump__(),
            port=self.__getport__(),
        )
        return result

    def instanciate(self):
        init_time = time.time()
        cms = self.serialize()
        results = {"target": self.url, "cms": cms["name"], "results": {}}

        if cms["name"]:
            instance = eval(cms["name"])(self.url, self.headers)

            if (
                not self.__getexploit__()
                and not self.__getwebinfo__()
                and not self.__getserveros__()
                and not self.__getcmsinfo__()
                and not self.__getdnsdump__()
                and not self.__getdomain__()
                and not self.__getport__()
            ):
                # Just print basic CMS info if no other options specified
                print(
                    "\n {0}[{1}Target{2}]{3} => {4}{5} \n ".format(
                        B, W, B, W, self.url, end
                    )
                )
                print("{0} −−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−".format(W))
                print(" {0} looking for cms".format(run))
                print(" {0} CMS : {1}".format(good, cms["name"]))

            if cms["exploit"]:
                results["results"]["exploits"] = instance.exploit()

            if cms["webinfo"]:
                results["results"]["webinfo"] = instance.webinfo()

            if cms["serveros"]:
                results["results"]["serveros"] = instance.serveros()

            if cms["cmsinfo"]:
                results["results"]["cmsinfo"] = instance.cmsinfo()

            if cms["dnsdump"]:
                results["results"]["dnsdump"] = instance.dnsdump()

            if cms["domain"]:
                results["results"]["domain"] = instance.domaininfo()

            if cms["port"]:
                results["results"]["ports"] = instance.ports(cms["port"])

            end_time = time.time()
            elapsed_time = end_time - init_time
            results["elapsed_time"] = elapsed_time

            return results
