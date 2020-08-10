import pandas as pd
import tldextract
import re
import validators
from urllib.parse import urlparse, urlencode
import socket
import whois
from datetime import date, datetime
import requests
from bs4 import BeautifulSoup
import OpenSSL
import ssl, socket
from progress.bar import IncrementalBar
import numpy as np
from preprocess.corpus_en import corpus_en
import operator
import onemillion
import time


class Pre_processing_EXTERN:
    def __init__(self, header_path = '', output_csv_path = ''):
        self.header_path = header_path
        self.output_csv_path = output_csv_path
        self.count = 0
        self.config_extern = {'DomainRegsitrationLength': self.get_DomainRegsitrationLength,#1.9
                           'AbnormalURL' : self.get_AbnormalURL,#1.18  LENTO
                           'AgeOfDomain' : self.get_AgeOfDomain,#1.24  LENTO
                           'DNSRecord': self.get_DNSRecord, #1.25  LENTO
                           'GoogleIndex': self.get_GoogleIndex, #1.27  LENTO
                           'SSLFinal_state':self.get_SSLFinal_state, #1.8 LENTO
                           'AgeSSL': self.get_AgeSSL, #new LENTO
                           'checkAlexa':self.get_checkAlexa,
                          }


    def set_featureslist(self, features_list):
        config_list = {}
        for key in self.config_extern.keys():
            if key in features_list:
                config_list[key] = self.config_extern[key]
        self.config_extern = config_list
        return list(config_list.keys())


    def get_DomainRegsitrationLength(self, page):
            domain = page['domain'] + '.' + page['suffix']
            try: 
                dinfo = page['whois']
                years = ((dinfo.expiration_date[0] - dinfo.creation_date[0])/(30*12)).days
                if years <= 1:
                    return 1
                else: 
                    return 0
            except:
                return 0


    def get_AbnormalURL(self, page):
        whoisinf = page['whois']
        lista = []
        try:
            x = whoisinf['name']
            lista.append(x)
        except:
            True
        try:
            lista.append(whoisinf['org'])
        except:
            True
            
        if whoisinf:
            for text in lista:
                if text != None:
                    if str(text).lower().find(page['domain'].lower()) > -1:
                        return 0
        return 1


    def get_AgeOfDomain(self, page):
        today = date.today()
        url = page['url']
        sslinfo = page['whois']
        if(sslinfo != None):
            try:
                if type(datetime.datetime(2020, 5, 23)) != type(sslinfo['creation_date']):
                    for creation in sslinfo['creation_date']:
                        if creation != None:
                            if((today - creation.date())/(6*30)).days <= 1:
                                return 1
                else:
                    if sslinfo['creation_date'] != None:
                        if((today - sslinfo['creation_date'].date())/(6*30)).days <= 1:
                            return 1
            except:
                return 1
        return 0


    def get_DNSRecord(self, page):
        url = page['url']

        sslinfo = page['whois']
        for key in sslinfo:
            if sslinfo[key] != None:
                return 0
        return 1

    def get_GoogleIndex(self, page):
        url = page['url']
        query = {'q': 'site:' + page['domain'] + '.' + page['suffix']}
        google = "https://www.google.com/search?" + urlencode(query)
        data = requests.get(google)
        data.encoding = 'ISO-8859-1'
        soup = BeautifulSoup(str(data.content), "html.parser")
        check = soup.findAll('a')
        if len(check)>23:
            return 1
        else:
            return 0

    def get_IssuerSSL(self, page):
        url = page['url']
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = page['ssl']
            if(cert):
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                if(x509):
                    return x509.get_issuer().CN
            return 'notfound'
        except:
            return 'notfound'


    def get_SSLFinal_state(self, page):
        url = page['url']
        self.count += 1
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = page['ssl']
            if(cert):
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                if(x509):
                    name = x509.get_issuer().CN
                    x1 = str(x509.get_notBefore()).replace('Z', '')
                    x2 = str(x509.get_notAfter()).replace('Z', '')
                    if(x1 and x2):
                        year2 = int(x2[2:6])
                        month2 = int(x2[6:8])
                        day2 = int(x2[8:10])

                        year1 = int(x1[2:6])
                        month1 = int(x1[6:8])
                        day1 = int(x1[8:10])
                        dif = datetime(year2, month2, day2) - datetime(year1, month1, day1)
                        dif = dif.days
                    else:
                        dif = -1
                else:
                    dif = -1
                    name = 'notfound'
            else:
                name = 'notfound'
                dif = -1    

            for org in ssl_org:
                if name.lower().find(org) > 0 and dif > 360:
                    return 0
            if name != 'notfound':
                return 1
            return 2
        except:
            return 2

    def get_AgeSSL(self, page):
        url = page['url']
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = page['ssl']
            if(cert):
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                if(x509):
                    x1 = str(x509.get_notBefore()).replace('Z', '')
                    x2 = str(x509.get_notAfter()).replace('Z', '')
                    if(x1 and x2):
                        year2 = int(x2[2:6])
                        month2 = int(x2[6:8])
                        day2 = int(x2[8:10])

                        year1 = int(x1[2:6])
                        month1 = int(x1[6:8])
                        day1 = int(x1[8:10])

                        dif = datetime(year2, month2, day2) - datetime(year1, month1, day1)
                        return dif.days
            return -1
        except:
            return -1


    def get_checkAlexa(self, page):
        domainsuf = page['domain'] + '.' + page['suffix']
        o = onemillion.OneMillion()
        if(o.domain_in_million(domainsuf)):
            return 0
        else:
            return 1


    def get_simplefeatures(self, dic_html):
        dic = {}
        page = {}
        page['url'] = dic_html['url']
        page['ip'] = dic_html['ip']
        page['html'] = dic_html['html']
        page['domain'] = tldextract.extract(page['url']).domain
        page['subdomain'] = tldextract.extract(page['url']).subdomain
        page['suffix'] = tldextract.extract(page['url']).suffix
        page['soup'] = BeautifulSoup(dic_html['html'], 'html.parser')
        page['whois'] = whois.whois(page['domain'] + '.'+ page['suffix'])
        try:
            page['ssl'] =  ssl.get_server_certificate((page['domain'] + '.'+ page['suffix'], 443))
        except:
            page['ssl'] = None
        for feature in self.config_extern.keys():
            dic[feature] = [self.config_extern[feature](page)]
        return dic


    def get_dffromlist(self, list_html):
        bar = IncrementalBar('EXTERN Features Progress:', max = len(list_html))
        page = self.get_simplefeatures(list_html[0])
        page['id'] = [list_html[0]['id']]     
        page['class'] = [list_html[0]['class']]   
        df_final = pd.DataFrame.from_dict(page)
        bar.next()
        for dic in list_html[1:]:
            
            page = self.get_simplefeatures(dic)
            page['id'] = [dic['id']] 
            page['class'] = [dic['class']]
            df2 = pd.DataFrame.from_dict(page)
            df_final = pd.concat([df_final, df2])
            bar.next()
        
        return df_final