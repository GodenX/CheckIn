#!/usr/bin/python3
# -*- coding:utf-8 -*-
# !Time    : 07/01/2020 15:48
# !@Author : Jackie Yang
# !File    : CheckIn.py
# !Project : CheckIn
# !Version : v0.1

import logging.handlers
import base64
import rsa
import requests
import http.cookiejar as cookiejar
import json
import os
import random
import re
import onetimepass
import time
import PyV8

# log wile be saved when use 'savelog'.
sys_path = os.path.split(os.path.realpath(__file__))[0]
if os.path.exists(sys_path + "/log"):
    pass
else:
    os.path.join(sys_path + "/log")
    os.mkdir(sys_path + "/log")
savelogname = sys_path + "/log/app.log"
savelogHandler = logging.handlers.TimedRotatingFileHandler(filename=savelogname, when="MIDNIGHT", backupCount=30)
savelogHandler.setFormatter(logging.Formatter('[%(asctime)s-%(levelname)s --> %(message)s]'))
savelog = logging.getLogger('savelog')
logging.getLogger('savelog').setLevel(logging.WARNING)
logging.getLogger('savelog').addHandler(savelogHandler)

# log wile be print when use 'printlog'. WARNINIG
printlogHandler = logging.StreamHandler()
printlogHandler.setFormatter(logging.Formatter('[%(asctime)s-%(levelname)s --> %(message)s]'))
printlog = logging.getLogger('printlog')
logging.getLogger("printlog").setLevel(logging.INFO)
logging.getLogger("printlog").addHandler(printlogHandler)

google_secret = "frgfrcd7zvzmszcv"
AppVersion = "1.4.9"
LiteonSecret = "0b82544d-937e-43c9-8bb2-bfd662a8340a"
publickey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJhk7tcp+LeQK0oJwPtJOO+gKvMgc8hLnYzQM9YbNKUSlop82E0atnGZrOqbXKPUPiOfFfvvgDjJvNuMEshAsT3fV4fsrrb2YQkSzCYdoSh9LetDoqASXZ6Il + heUdz0w0XVjI8lD0DiXMIjbFbrya4p1OE3EtM + JJd0L500yB0QIDAQAB"
client_id = "9fc8a699-4f09-4b99-b15f-217d2e569eb1"
Ticket = ""

# convent the format of key from str to rsa format.
def str2key(var):
    try:
        b_str = base64.b64decode(var)
        if len(b_str) < 162:
            return False
        hex_str = ""
        for x in bytes(b_str):
            h = hex(x)[2:]
            h = h.rjust(2, '0')
            hex_str += h
        m_start = 29 * 2
        e_start = 159 * 2
        m_len = 128 * 2
        e_len = 3 * 2
        modulus = int(hex_str[m_start:m_start + m_len], 16)
        exponent = int(hex_str[e_start:e_start + e_len], 16)
        return rsa.PublicKey(modulus, exponent)
    except Exception as e:
        savelog.error("srt2key convent error: " + str(e))
        printlog.error("srt2key convent error: " + str(e))
        return False


# google authenticator
def calGoogleCode():
    googleCode = onetimepass.get_totp(google_secret)
    googleCode = "%06d" % googleCode
    return googleCode

# gernate the 32bit uuid
def newGuid():
    guid = ""
    for x in range(1,32):
        guid += random.sample('0123456789abcdef',1)[0]
        if x == 8 or x == 12 or x == 16 or x == 20:
            guid += "-"
    return guid


class AppConnect(object):
    def __init__(self, secret=LiteonSecret, publickey=publickey, client_id = client_id):
        self.secret = secret
        self.publickey = publickey
        self.client_id = client_id
        self.key = {}

    # rsa encrypt
    def _rsaEncrypt(self, var):
        printlog.debug("encrypt start: " + var)
        return rsa.encrypt(var.encode(), str2key(self.publickey))
            
    # get ticket
    def getTicket(self):
        encryptionstr = ""
        try:
            encryptionstr = bytes.decode(base64.b64encode(self._rsaEncrypt(self.secret)))
            printlog.debug("encrypt end: " + encryptionstr)
        except Exception as e:
            savelog.error("encrypt error: " + str(e))
            printlog.error("encrypt error: " + str(e))
            return False

        try:
            url = "https://mobileportalapi.liteon.com/api/AppTicket/GetTicket"
            payload = {"rsaStr": encryptionstr}
            headers = {"Host": "mobileportalapi.liteon.com",
                       "Content-Type": "application/x-www-form-urlencoded",
                       "Origin": "file://",
                       "Connection": "keep-alive",
                       "Accept": "*/*",
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Accept-Language": "zh-cn",
                       "Accept-Encoding": "gzip, deflate, br",
                       "X-Requested-With": "XMLHttpRequest"}
            ResponseData = requests.post(url, headers=headers, data=payload)
            printlog.debug("Get Ticket ResponseData: " + ResponseData.text)
            var = json.loads(ResponseData.text)
            if var["ResponseState"] == 1:
                self.key["ticket"] = var["ResponseData"]
                printlog.info("Get Ticket Success")
            else:
                self.key["ticket"] = ""
                printlog.info("Get Ticket Failed")
            return self.key["ticket"]
        except Exception as e:
            savelog.error("--------->get ticket error: " + str(e))
            printlog.error("--------->get ticket error: " + str(e))
            return False

    # get setting
    def getSetting(self):
        try:
            url = "https://mobileportalapi.liteon.com/api/AppSetting/GetSetting"
            headers = {"Host": "mobileportalapi.liteon.com", 
                       "Connection": "keep-alive",
                       "Accept": "*/*",
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Accept-Language": "zh-cn",
                       "Accept-Encoding": "gzip, deflate, br",
                       "X-Requested-With": "XMLHttpRequest"}
            if "ticket" in self.key:
                return False
            else:
                headers["Authorization"] = "BasicAuth " + self.key["ticket"]
            ResponseData = requests.get(url, headers=headers)
            printlog.debug("Get Setting ResponseData: " + ResponseData.text)
            var = json.loads(ResponseData.text)
            if var["ResponseState"] == 1:
                printlog.info("Get Setting Success")
                return True
            else:
                printlog.info("Get Setting Failed")
                return False
        except Exception as e:
            savelog.error("--------->get setting error: " + str(e))
            printlog.error("--------->get setting error: " + str(e))
            return False

    # get version
    def getVersion(self):
        try:
            url = "https://mobileportalapi.liteon.com/api/AppVersion/GetVersion"
            headers = {"Host": "mobileportalapi.liteon.com", 
                       "Connection": "keep-alive",
                       "Accept": "*/*",
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Accept-Language": "zh-cn",
                       "Accept-Encoding": "gzip, deflate, br",
                       "X-Requested-With": "XMLHttpRequest"}
            if "ticket" in self.key:
                return False
            else:
                headers["Authorization"] = "BasicAuth " + self.key["ticket"]
            ResponseData = requests.get(url, headers=headers)
            printlog.debug("Get Version ResponseData: " + ResponseData.text)
            var = json.loads(ResponseData.text)
            if var["ResponseState"] == 1:
                if var["ResponseObject"]["Ios"] == AppVersion:
                    printlog.info("Get Version Success: latest")
                    return True
                else:
                    printlog.info("Get Version Success: update")
                    return "update"
            else:
                printlog.info("Get Version Failed")
                return False
        except Exception as e:
            savelog.error("--------->get version error: " + str(e))
            printlog.error("--------->get version error: " + str(e))
            return False

    # login windows
    def loginWindows_instance(self):
        try:
            url = "https://login.windows.net/common/discovery/instance"
            params = {"api-version": "1.1",
                      "authorization_endpoint": "https://login.windows.net/liteon.onmicrosoft.com/oauth2/authorize"}
            headers = {"Accept": "application/json",
                       "x-client-SKU": "PCL.IOS",
                       "x-client-Ver": "4.5.0.0",
                       "x-client-OS": "13.3",
                       "x-client-DM": "iPhone",
                       "x-ms-PKeyAuth": "1.0",
                       "client-request-id": newGuid(),
                       "return-client-request-id": "true",
                       "Connection": "keep-alive",
                       "Host": "login.windows.net"}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.get(url, headers=headers, params=params)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows Instance ResponseData: " + ResponseData.text)
            if "tenant_discovery_endpoint" in json.loads(ResponseData.text):
                printlog.info("Login Windows Instance Success")
            else:
                printlog.info("Login Windows Instance Failed")
        except Exception as e:
            savelog.error("--------->login windows instance error: " + str(e))
            printlog.error("--------->login windows instance error: " + str(e))
        finally:
            s.close()

    def loginWindows_authorize(self):
        try:
            url = "https://login.microsoftonline.com/liteon.onmicrosoft.com/oauth2/authorize"
            params = {"resource": "https://graph.microsoft.com",
                      "client_id": self.client_id,
                      "response_type": "code",
                      "haschrome": "1",
                      "redirect_uri": "https://oath2.liteon.com",
                      "login_hint": "jackieyang@liteon.com",
                      "client-request-id": newGuid(),
                      "x-client-SKU": "PCL.iOS",
                      "x-client-Ver": "4.5.0.0",
                      "x-client-OS": "13.3",
                      "x-client-DM": "iPhone"}
            headers = {"Host": "login.microsoftonline.com",
                       "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Accept-Language": "zh-cn",
                       "Accept-Encoding": "gzip, deflate, br",
                       "Connection": "keep-alive"}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.get(url, headers=headers, params=params)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows authorize header: " + str(ResponseData.headers))
            with open(sys_path + '/loginWindows_authorize.html', 'w') as f: # for debug
                f.write(ResponseData.text)                                  # save result as html
            self.key["canary"] = re.search( "\"canary\":\"\S+?\"", ResponseData.text).group(0)[10:-1]
            self.key["ctx"] = re.search( "\"sCtx\":\"\S+?\"", ResponseData.text).group(0)[8:-1]
            self.key["flowToken"] = re.search( "\"FlowToken\":\"\S+?\"", ResponseData.text).group(0)[13:-1]
            self.key["hpgrequestid"] = ResponseData.headers["x-ms-request-id"]
            printlog.info("Login Windows Authorize Success")
        except Exception as e:
            savelog.error("--------->login windows authorize error: " + str(e))
            printlog.error("--------->login windows authorize error: " + str(e))
        finally:
            s.close()

    def loginWindows_msftauth1(self):
        try:
            url = "https://aadcdn.msftauth.net/ests/2.1/content/cdnbundles/ux.old.converged.login.pcore.min_gi3zhqs3puphhu0ryfq-5q2.js"
            headers = {"Host": "aadcdn.msftauth.net",
                    "Origin": "https://login.microsoftonline.com",
                    "Connection": "keep-alive",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "Accept-Language": "zh-cn",
                    "Referer": "https://login.microsoftonline.com/",
                    "Accept-Encoding": "gzip, deflate, br",}
            ResponseData = requests.get(url, headers=headers)
            printlog.debug("Login Windows msftauth1 header: " + str(ResponseData.headers))
            js = ResponseData.content
            

            printlog.info("Login Windows msftauth1 Success")
        except Exception as e:
            savelog.error("--------->login windows msftauth1 error: " + str(e))
            printlog.error("--------->login windows msftauth1 error: " + str(e))
        finally:
            s.close()

    def loginWindows_login(self):
        try:
            url = "https://login.microsoftonline.com/liteon.onmicrosoft.com/login"
            headers = {"Host": "login.microsoftonline.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://login.microsoftonline.com",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "Referer": "https://login.microsoftonline.com/",
                    "Accept-Language": "zh-cn"}
            payload = {"i13": "0",
                       "login": "jackieyang@liteon.com",
                       "loginfmt": "jackieyang@liteon.com",
                       "type":	"11",
                       "LoginOptions":	"3",
                       "lrt": None,
                       "lrtPartition": None,
                       "hisRegion": None,
                       "hisScaleUnit": None,
                       "passwd": "AAasdfghjkl;'",
                       "ps": "2",
                       "psRNGCDefaultType": None,
                       "psRNGCEntropy": None,
                       "psRNGCSLK": None,
                       "canary": self.key["canary"],
                       "ctx": self.key["ctx"],
                       "hpgrequestid":	self.key["hpgrequestid"],
                       "flowToken": self.key["flowToken"],
                       "PPSX": None,
                       "NewUser": "1",
                       "FoundMSAs": None,
                       "fspost": "0",
                       "i21": "0",
                       "CookieDisclosure":	"0",
                       "IsFidoSupported": "0",
                       "isSignupPost":	"0",
                       "i2": "1",
                       "i17": None,
                       "i18": None,
                       "i19": "10998"}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.post(url, headers=headers, data=payload)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows login header: " + str(ResponseData.headers))
            with open(sys_path + '/loginWindows_login.html', 'w') as f: # for debug
                f.write(ResponseData.text)                              # save result as html
            self.key["hpgact"] = re.search( "\"hpgact\":\S+?,", ResponseData.text).group(0)[9:-1]
            self.key["canary"] = re.search( "\"canary\":\"\S+?\"", ResponseData.text).group(0)[10:-1]
            self.key["hpgid"] = re.search( "\"hpgid\":\S+?,", ResponseData.text).group(0)[8:-1]
            self.key["hpgrequestid"] = ResponseData.headers["x-ms-request-id"]
            self.key["ctx"] = re.search( "\"sCtx\":\"\S+?\"", ResponseData.text).group(0)[8:-1]
            self.key["flowToken"] = re.search( "\"FlowToken\":\"\S+?\"", ResponseData.text).group(0)[13:-1]
            printlog.info("Login Windows Lpipogin Success")
        except Exception as e:
            savelog.error("--------->login windows login error: " + str(e))
            printlog.error("--------->login windows login error: " + str(e))
        finally:
            s.close()

    def loginWindows_msftauth2(self):
        try:
            url = "https://aadcdn.msftauth.net/ests/2.1/content/cdnbundles/ux.old.converged.sa.core.min__y_bduaoxptw0cdbw0re6a2.js"
            headers = {"Host": "aadcdn.msftauth.net",
                    "Origin": "https://login.microsoftonline.com",
                    "Connection": "keep-alive",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "Accept-Language": "zh-cn",
                    "Referer": "https://login.microsoftonline.com/",
                    "Accept-Encoding": "gzip, deflate, br",}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.get(url, headers=headers)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows msftauth2 header: " + str(ResponseData.headers))
            with open(sys_path + '/loginWindows_msftauth2.html', 'w') as f: # for debug
                f.write(ResponseData.text)                                  # save result as html

            printlog.info("Login Windows msftauth2 Success")
        except Exception as e:
            savelog.error("--------->login windows msftauth2 error: " + str(e))
            printlog.error("--------->login windows msftauth2 error: " + str(e))
        finally:
            s.close()

    def loginWindows_beginAuth(self):
        try:
            url = "https://login.microsoftonline.com/common/SAS/BeginAuth"
            headers = {"Host": "login.microsoftonline.com",
                    "Accept": "application/json",
                    "hpgact": self.key["hpgact"],
                    "canary": self.key["canary"],
                    "Accept-Language": "zh-cn",
                    "hpgid": self.key["hpgid"],
                    "hpgrequestid": self.key["hpgrequestid"],
                    "Accept-Encoding": "gzip, deflate, br",
                    "Origin": "https://login.microsoftonline.com",
                    "client-request-id": newGuid(),
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                    "Referer": "https://login.microsoftonline.com/",
                    "Connection": "keep-alive",
                    "Content-Type": "application/json; charset=utf-8"}
            self.key["client-request-id"] = headers["client-request-id"]
            payload = {"AuthMethodId": "PhoneAppOTP",
                    "Method": "BeginAuth",
                    "ctx": self.key["ctx"],
                    "flowToken": self.key["flowToken"]}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.post(url, headers=headers, data=payload)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows beginAuth header: " + str(ResponseData.headers))
            printlog.info("Login Windows beginAuth header: " + str(ResponseData.text))
            # self.key["hpgact"] = re.search( "\"hpgact\":\S+?,", ResponseData.text).group(0)[9:-1]
            # self.key["canary"] = re.search( "\"canary\":\"\S+?\"", ResponseData.text).group(0)[10:-1]
            # self.key["hpgid"] = re.search( "\"hpgid\":\S+?,", ResponseData.text).group(0)[8:-1]
            # self.key["hpgrequestid"] = ResponseData.headers["x-ms-request-id"]
            # self.key["sessionId"] = re.search( "\"sessionId\":\"\S+?\"", ResponseData.text).group(0)[12:-1]
            # printlog.info("Login Windows beginAuth Success")
        except Exception as e:
            savelog.error("--------->login windows beginAuth error: " + str(e))
            printlog.error("--------->login windows beginAuth error: " + str(e))
        finally:
            s.close()

    def loginWindows_endAuth(self):
        try:
            url = "https://login.microsoftonline.com/common/SAS/EndAuth"
            headers = {"Host": "login.microsoftonline.com",
                       "Accept": "application/json",
                       "hpgact": self.key["hpgact"],
                       "canary": self.key["canary"],
                       "Accept-Language": "zh-cn",
                       "hpgid": self.key["hpgid"],
                       "hpgrequestid": self.key["hpgrequestid"],
                       "Accept-Encoding": "gzip, deflate, br",
                       "Origin": "https://login.microsoftonline.com",
                       "client-request-id": self.key["client-request-id"],
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Referer": "https://login.microsoftonline.com/",
                       "Connection": "keep-alive",
                       "Content-Type": "application/json; charset=utf-8"}
            payload = {"Method":"EndAuth",
                       "SessionId":self.key["sessionId"],
                       "FlowToken": self.key["flowToken"],
                       "Ctx": self.key["ctx"],
                       "AuthMethodId": "PhoneAppOTP",
                       "AdditionalAuthData": calGoogleCode(),
                       "PollCount": 1}
            s = requests.Session()
            if os.path.exists("cookies.txt"):
                s.cookies = cookiejar.LWPCookieJar(filename="cookies.txt")
                s.cookies.load(filename="cookies.txt", ignore_discard=True)
            else:
                s.cookies = cookiejar.LWPCookieJar()
            ResponseData = s.post(url, headers=headers, data=payload)
            s.cookies.save(filename="cookies.txt", ignore_discard=True, ignore_expires=True)
            printlog.debug("Login Windows endAuth header: " + str(ResponseData.headers))
            with open(sys_path + '/loginWindows_endAuth.html', 'w') as f: # for debug
                f.write(ResponseData.text)                                  # save result as html

            printlog.info("Login Windows endAuth Success")
        except Exception as e:
            savelog.error("--------->login windows endAuth error: " + str(e))
            printlog.error("--------->login windows endAuth error: " + str(e))
        finally:
            s.close()

    # def loginWindows_processAuth(self):
    #     url = "https://login.microsoftonline.com/common/SAS/ProcessAuth"
    #     headers = {"Host": "login.microsoftonline.com",
    #                "Content-Type": "application/x-www-form-urlencoded",
    #                "Origin": "https://login.microsoftonline.com",
    #                "Accept-Encoding": "gzip, deflate, br",
    #                "Connection": "keep-alive",
    #                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    #                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    #                "Referer": "https://login.microsoftonline.com/",
    #                "Accept-Language": "zh-cn"}
    #     payload = {"type": "19",
    #                "GeneralVerify": "false",
    #                "request":
    #                "mfaLastPollStart": Timestamp=2020-01-17T00:22:08Z
    #                "mfaLastPollEnd": Timestamp=2020-01-17T00:22:25Z
    #                "mfaAuthMethod": "PhoneAppOTP",
    #                "canary":
    #                "otc":
    #                "login": "jackie.yang@liteon.com",
    #                "flowToken":
    #                "hpgrequestid":
    #                "sacxt": None,
    #                "i2": None,
    #                "i17": None,
    #                "i18": None,
    #                "i19": "19415"}


    # get real mList
    def getRealmList(self):
        try:
            url = "https://mobileportalapi.liteon.com/api/AppRealm/GetRealmList"
            headers = {"Host": "mobileportalapi.liteon.com",
                       "Content-Type": "application/json",
                       "Origin": "file://",
                       "Accept-Encoding": "gzip, deflate, br",
                       "Content-Length": "30",
                       "Connection": "keep-alive",
                       "Accept": "application/json",
                       "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                       "Accept-Language": "zh-cn",
                       "X-Requested-With": "XMLHttpRequest"}
            if self.ticket is False:
                return False
            else:
                headers["Authorization"] = "BasicAuth " + self.ticket
            payload = {"region": "public", "type": "0"}
            ResponseData = requests.post(url, headers=headers, data=payload)
            printlog.info("Login Windows ResponseData: " + ResponseData.text)
            # var = json.loads(ResponseData.text)
        except Exception as e:
            savelog.error("--------->login windows error: " + str(e))
            printlog.error("--------->login windows error: " + str(e))
            return False

    def run(self):
        self.getTicket()
        self.getSetting()
        self.getVersion()
        self.loginWindows_instance()
        self.loginWindows_authorize()
        self.loginWindows_msftauth1()
        self.loginWindows_login()
        self.loginWindows_msftauth2()
        self.loginWindows_beginAuth()
        # self.loginWindows_endAuth()
        # self.getRealmList()


if __name__ == "__main__":
    conn = AppConnect()
    conn.run()
    # timeArray = time.strptime("2020-01-17T00:22:25Z", "%Y-%m-%dT%H:%M:%SZ")
    # timestamp = time.mktime(timeArray)
    # print(timestamp)