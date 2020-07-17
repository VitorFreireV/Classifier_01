import pandas as pd
from preprocess.knowledgebase import *
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
#from config import *
from preprocess.gib_detect import gib_RandomString
import stringdist
import numpy as np
from preprocess.corpus_en import corpus_en
import operator
import onemillion
import time

class Pre_processing_URL:
    def __init__(self, header_path = '', output_csv_path = ''):
        self.header_path = header_path
        self.output_csv_path = output_csv_path
        self.count = 0
        self.config_url = {'UsingIPAddress1': self.get_UsingIPAddress1, #1.1
                         
                           'URLlengthRule1':self.get_URLlengthRule1,  #1.2  
                           'TinyService':self.get_TinyService,  #1.3 
                           'checkArrobaURL': self.get_checkArroba_URL, #1.4, 2.5  
                           'checkRedirectURL' : self.get_checkRedirect_URL, #1.5, 2.24
                           'checkDashDomain': self.get_checkDashDomain, #1.6
                           'checkSubDomainMulSubDomain': self.get_checkSubDomainMulSubDomain,#1.7
                           
                           'DomainRegsitrationLength': self.get_DomainRegsitrationLength,#1.9
                           'checkHTTPSDomainURL': self.get_checkHTTPSDomain_URL,#1.12, 2.20
                           'AbnormalURL' : self.get_AbnormalURL,#1.18  LENTO
                           'AgeOfDomain' : self.get_AgeOfDomain,#1.24  LENTO
                           'DNSRecord': self.get_DNSRecord, #1.25  LENTO
                           'GoogleIndex': self.get_GoogleIndex, #1.27  LENTO
                           'StatisticalReports': self.get_StatisticalReports, # 1.29
                           #'SSLFinal_state2':self.get_SSLFinal_state2, #1.8 
                           #'SSLFinal_state':self.get_SSLFinal_state, #1.8 LENTO
                           
                           #'AgeSSL2': self.get_AgeSSL2, #new
                           #'AgeSSL': self.get_AgeSSL, #new LENTO

                           'numDotsURL': self.get_numDots_URL, #2.1
                           'NumDotSubDomain' : self.get_numDots_SubDomain, #2.2         
                           'pathLevelURL' : self.get_PathLevel_URL,  #2.3
                           'URLlength':self.get_URLlength,  #2.4
                           'NumDashURL': self.get_NumDash_URL, # 2.5
                           'NumDashDomain' : self.get_NumDashDomain_URL, # 2.6
                           'checkTildeSymbolURL': self.get_TildeSymbol_URL, # 2.8
                           'NumUnderscoreURL' : self.get_NumUnderscore_URL, # 2.9
                           'NumPercentURL' : self.get_NumPercent_URL, # 2.10
                           'NumAmpersandURL': self.get_NumAmpersand_URL, # 2.12
                           'QueryComponents': self.get_QueryComponents, #2.11
                           'NumHashURL' : self.get_NumHash_URL, #2.13
                           'NumNumericCharsURL' : self.get_NumNumericChars_URL, #2.14
                           'NoHTTPS' : self.get_NoHTTPS, #2.15

                           'DomainInSubdomains' : self.get_DomainInSubdomains, # 2.19
                           'DomainInPaths' : self.get_DomainInPaths, #2.20
                           'HostnameLenth' : self.get_HostnameLength, # 2.21
                           'PathLength':self.get_PathLengthURL, #2.22
                           'QueryLength' : self.get_QueryLength, #2.23
                           'NumSensitiveWords': self.get_NumSensitiveWords, # 2.25
                        

                           'NumArrobaURL': self.get_NumArroba_URL,                   
                           'KnowLTD': self.get_checkKnowLTD,
                           'get_PositionTLD' : self.get_PositionTLD, #F5
                           'BrandNameURL' : self.get_BrandNameURL, #3.2
                           'numDots_URLRule4':self.get_numDots_URLRule4, #4.1
                           'SpecialSymbol4':self.get_SpecialSymbol4, #4.2
                           'URLlengthRule4':self.get_URLlengthRule4, #4.3
                           'SuspiciousInURL':self.get_SuspiciousInURL, #4.4
                           'httpCountInURL':self.get_httpCountInURL, #4.6
                           'BrandNameDomain':self.get_BrandNameDomain,
                           'NumNumericChars_Path':self.get_NumNumericChars_Path,
                           'NumNumericChars_Domain':self.get_NumNumericChars_Domain,
                           'NumNumericChars_Subdomain':self.get_NumNumericChars_Subdomain,
                           'RandomDomain':self.get_RandomDomain,
                           'RandomString':self.get_RandomString,
                           'DomainLength':self.get_DomainLengthURL,
                           'SubdomainLength':self.get_SubdomainLengthURL,
                           'checkWWW':self.get_checkWWW,
                           'checkCOM':self.get_checkCOM,
                           'numInterrogation':self.get_numInterrogation,
                           'numBar':self.get_numBar,
                           'numEqual':self.get_numEqual,
                           'numArroba':self.get_numArroba,
                           'checkAlexa':self.get_checkAlexa,
                          }
        self_config_html = {}

    def ParserURL(self, url):
        #specialcarater = '.!#$%&()*+,-:;<=>?@[\]^_{|}~'
        specialcarater = '?/.=&'
        parserlist = [url]
        for caracter in specialcarater:
            for word in parserlist:
                if word.split(caracter) != [word]:
                    parserlist.remove(word)
                    parserlist += word.split(caracter) 
        parserlist.remove('')
        return parserlist

    def DecompuserWordModule(self, word, word_list, data):
        word = ''.join(i for i in word if not i.isdigit())
        other_words = []
        if(word in corpus_en):
            word_list.append(word) 
            other_words.append(word)
            return [word], [word] , other_words
        else:
            splits = [word[i: j] for i in range(len(word)) 
                        for j in range(i + 1, len(word) + 1)] 
            #ordenando
            dic_split = {}
            for w in splits:
                if(len(w) > 2):
                    dic_split[w] = len(w)
            
            dic_split = dict(sorted(dic_split.items(), key=operator.itemgetter(1), reverse = True))
            # check valid word
            word_list_dec = []
            for w in dic_split.keys():
                if w in corpus_en:
                    word_list_dec.append(w)
                    other_words.append(w)
            
            # remove false postive
            size = len(word_list_dec)-1
            false_list = []
            for i in range(size+1):
                for j in range(size+1):
                    if(j!= (size-i)):
                        if(word_list_dec[j].find(word_list_dec[size - i]) > -1):
                            if(word_list_dec[size - i] not in false_list):
                                false_list.append(word_list_dec[size - i])
            for false in false_list:  
                word_list_dec.remove(false)
            
            word_list += word_list_dec
            return dic_split, word_list_dec, other_words

    def MaliciusnessAnalysis(self, word_list, data, brand_list, keyword_list):
        check_similary = []
        data['ConsecutiveCharacterRepeat'] = 0
        for word in word_list:
            if word.lower() in dic_BrandNames.keys():
                brand_list.append(word.lower())
                
            if word.lower() in sensitive_list:
                keyword_list.append(word.lower())
        data['KeywordCount'] = len(keyword_list)
        data['BrandNameCount'] = len(brand_list)
        # get targets data
        list_key = []
        count_key = 0
        for word in keyword_list:
            if word not in list_key:
                count_key += 1
                list_key.append(word)
        list_brand = []
        count_brand = 0
        for word in brand_list:
            if word not in list_brand:
                count_brand += 1
                list_brand.append(word)
        data['TargetBrandNameCount'] = count_brand
        data['TargetKeywordCount'] = count_key

        for word in word_list:
            if word.lower() not in brand_list and word.lower() not in keyword_list:
                check_similary.append(word.lower()) 
        # for brandnames
        similar_word_list = []
        for word in check_similary:
            for brand in dic_BrandNames.keys(): 
                if((stringdist.levenshtein(word, brand) < 2) and word not in similar_word_list):
                    similar_word_list.append(word)
                    data['ConsecutiveCharacterRepeat'] = 1

        data['SimilarBrandNameCount'] = len(similar_word_list)

        for word in check_similary:
            for sens in sensitive_list: 
                if(stringdist.levenshtein(word, sens) < 2 and word not in similar_word_list):
                    #print(word, sens)
                    similar_word_list.append(word)
                    data['ConsecutiveCharacterRepeat'] = 1
        data['SimilarKeywordCount'] = len(similar_word_list) - data['SimilarBrandNameCount']
                    
        return similar_word_list

    def preprocessingURL(self, page, tag):
        data = {}
        url = page[tag]
        parserlist = self.ParserURL(url)
        ## PEGANDO OS DADOS DA RAW LIST
        data['RawWordCount'] = len(parserlist) # 1
        list_tam = []
        for token in parserlist:
            list_tam.append(len(token))
        list_tam = np.array(list_tam)
        data['AvaregeWordLength'] = list_tam.mean()
        data['LongestWordLength'] = list_tam.max()
        data['ShortestWordLength'] = list_tam.min()
        data['StandardDerivation'] = list_tam.std()

        # check brand name or keyword
        brand_list = []
        keyword_list = []
        for word in parserlist:
            if word.lower() in dic_BrandNames.keys():
                brand_list.append(word.lower())
                parserlist.remove(word)
            if word.lower() in sensitive_list:
                keyword_list.append(word.lower())
                parserlist.remove(word)
        
        #data['KeywordCount'] = len(keyword_list)
        #data['BrandNameCount'] = len(brand_list)


        #check random word dection
        word_list = []
        randomword_list = []
        adjc_list = []
        dec_list = []
        other_list = []
        for word in parserlist:
            if(not gib_RandomString(word)):
                randomword_list.append(word)
            elif(len(word)<=7):
                word_list.append(word)
            else:
                adjc_, dec_ , other = self.DecompuserWordModule(word, word_list, data)
                other_list += other
                adjc_list += adjc_
                dec_list += dec_
        data['AdjacentWordCount'] = len(adjc_list)
        sum = 0.0
        for word in adjc_list:
            sum += len(word)

        if sum != 0.0:
            data['AverageAdjacentWordLength'] = sum/len(adjc_list)
        else:
            data['AverageAdjacentWordLength'] = 0.0
        data['SeparatedWordCount'] = len(dec_list)    
        data['OtherWordsCount'] = len(other_list)    
        data['RandomWordCount'] = len(randomword_list)        
        # maliciusness analysis
        self.MaliciusnessAnalysis(word_list, data, brand_list, keyword_list)
        return data

    def get_checkAlexa(self, page, tag):
        #domainsuf = tldextract.extract(page[tag]).domain +'.' +tldextract.extract(page[tag]).suffix 
        domainsuf = page['domain'] + '.' + page['suffix']
        o = onemillion.OneMillion()
        if(o.domain_in_million(domainsuf)):
            return 0
        else:
            return 1

    def get_numArroba(self, page, tag):
        return page[tag].count('@')

    def get_numEqual(self, page, tag):
        return page[tag].count('=')

    def get_numBar(self, page, tag):
        return page[tag].count('/')

    def get_numInterrogation(self, page, tag):
        return page[tag].count('?')    

    def get_checkCOM(self, page, tag):
        #subdomain = tldextract.extract(page[tag]).subdomain
        #domain = tldextract.extract(page[tag]).domain

        if page['subdomain'].find('com') > -1:
            return 1
        if page['domain'].find('com') > -1:
            return 1
        return 0

    def get_checkWWW(self, page, tag):
        #subdomain = tldextract.extract(page[tag]).subdomain
        #domain = tldextract.extract(page[tag]).domain
        subdomain = page['subdomain']
        domain = page['domain']
        if subdomain[:3] == 'www':
            subdomain = subdomain[3:]
        if subdomain.find('www') > -1:
            return 1
        if domain.find('www') > -1:
            return 1
        return 0

    def get_RandomDomain(self, page, tag):
        #domain = tldextract.extract(page[tag]).domain
        if not gib_RandomString(page['domain']):
            return 1
        else:
            return 0
        
    def get_RandomString(self, page, tag):
        parser = self.ParserURL(page[tag])
        for word in parser:
            if not gib_RandomString(word):
                return 1
        return 0

    def get_NoHTTPS(self, page, tag):
        url = page[tag]
        if url[4:].find('https') > -1:
            return 1
        return 0

    def get_SSLFinal_state2(self, page, tag):
        age = page['age']
        name = page['sslissuer']
        for org in ssl_org:
            if name.lower().find(org) > 0 and age > 360:
                return 0
            if name != 'notfound' or name != 'None':
                return 1
        return 2


    def get_SSLFinal_state(self, page, tag):
        url = page[tag]
        #domainsuf = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        #print(self.count, domainsuf)
        self.count += 1
        #print(domainsuf)
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = ssl.get_server_certificate((domainsuf, 443))
            #print('pegou cert')
            if(cert):
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                #print('pegou x509')
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
            # rule 
            # verify name
            for org in ssl_org:
                if name.lower().find(org) > 0 and dif > 360:
                    return 0
            if name != 'notfound':
                return 1
            return 2
        except:
            return 2
        
    def get_IssuerSSL(self, page, tag):
        url = page[tag]
        #domainsuf = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = ssl.get_server_certificate((domainsuf, 443))
            if(cert):
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                if(x509):
                    return x509.get_issuer().CN
            return 'notfound'
        except:
            return 'notfound'

    def get_AgeSSL2(self, page, tag):
        return page['age']
    

    def get_AgeSSL(self, page, tag):
        url = page[tag]
        #domainsuf = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        domainsuf = page['domain'] + '.' + page['suffix']
        try:
            cert = ssl.get_server_certificate((domainsuf, 443))
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


    def get_httpCountInURL(self, page, tag):
        url = page[tag]
        if url.count('http')>1:
            return 1
        return 0

    def get_SuspiciousInURL(self, page, tag):
        url = page[tag]
        count = 0
        for word in sensitive_list:
            if(url.find(word)>-1):
                return 1
        return 0


    def get_URLlengthRule4(self, page, tag):
        number = self.get_URLlength(page, tag)
        if number >= 74:
            return 1
        return 0

    def get_SpecialSymbol4(self, page, tag):
        url = page[tag]
        if url.count('@') > 0:
            return 1
        if url.count('-') > 0:
            return 1
        return 0

    def get_numDots_URLRule4(self, page, tag):
        number = self.get_numDots_URL(page, tag)
        if number >= 4:
            return 1
        return 0

    def get_NumSensitiveWords(self, page, tag):
        url = page[tag]
        count = 0
        for word in sensitive_list:
            count += url.count(word)
        return count


    def get_URLlengthRule1(self, page, tag):
        number = self.get_URLlength(page, tag)
        if number < 54:
            return 0
        elif number <= 75:
            return 1
        else:
            return 2

    def get_StatisticalReports(self, page, tag):
        ip = page['ip']
        url = page[tag]
        #domainsuf = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        domainsuf = page['domain'] + '.' + page['suffix']
        if domainsuf.lower in top_domain:
            return 1
        if ip in top_ip:
            return 1
        return 0


    def get_GoogleIndex(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #suffix = tldextract.extract(url).suffix
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

    def get_DNSRecord(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #suffix = tldextract.extract(url).suffix
        #sslinfo = whois.whois(page['domain'] + '.' + page['suffix'])
        sslinfo = page['whois']
        for key in sslinfo:
            if sslinfo[key] != None:
                return 0
        return 1

    def get_AgeOfDomain(self, page, tag):
        today = date.today()
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #suffix = tldextract.extract(url).suffix
        #sslinfo = whois.whois(page['domain'] + '.' + page['suffix'])
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

    def get_AbnormalURL(self, page, tag):
        #domain = tldextract.extract(page[tag]).domain
        #suffix = tldextract.extract(page[tag]).suffix
        #whoisinf = whois.whois(page['domain'] + '.' + page['suffix'])
        whoisinf = page['whois']
        result = 1
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
                        result = 0
        return result


    def get_DomainRegsitrationLength(self, page, tag):
        #domain = tldextract.extract(page[tag]).domain + '.' + tldextract.extract(page[tag]).suffix
        domain = page['domain'] + '.' + page['suffix']
        try: 
            #print(domain)    
            #dinfo = whois.whois(domain)
            dinfo = page['whois']
            #sslinfo = whois.query(domain).__dict__
            years = ((dinfo.expiration_date[0] - dinfo.creation_date[0])/(30*12)).days
            #years = ((sslinfo['expiration_date'] - sslinfo['creation_date'])/(30*12)).days
            if years <= 1:
                return 1
            else: 
                return 0
        except:
            return 0

    
  
    def get_checkSubDomainMulSubDomain(self, page, tag):
        #subdomain = tldextract.extract(page[tag]).subdomain
        subdomain = page['subdomain']
        if(subdomain[:4] == 'www.'):
            subdomain = subdomain[4:]
        if subdomain.count('.') > 3:
            return 1
        elif subdomain.count('.') == 3:
            return 2
        else:
            return 0

    def get_checkDashDomain(self, page, tag):
        url = page[tag] 
        #domain = tldextract.extract(url).domain
        if page['domain'].find('-') > -1 :
            return 1
        else:
            return 0
            


    def get_checkArroba_URL(self, page, tag):
        if (self.get_NumArroba_URL(page, tag) == 0): 
            return 0
        else:
            return 1 

    def get_TinyService(self, page, tag):
        url = page['url1'].split('/',3)[2]
        for service in list_TINYs:
            if url.find(service) > -1:
                return 1
        return 0

    def get_URLlength(self, page, tag):
        url = page[tag]
        return len(url)

    def get_BrandNameDomain(self, page, tag):
        #domain = tldextract.extract(page[tag]).domain
        for brand in dic_BrandNames:
            if(page['domain'].find(brand) > -1):
                return 1
        return 0


    def get_BrandNameURL(self, page, tag):
        url = page[tag]
        for brand in dic_BrandNames:
            if(url.find(brand) > -1):
                return 1
        return 0


    def get_ParametersLength(self, page, tag):
        url = page[tag]
        params = urlparse(url).params
        if(params):
            return len(params)
        else:
            return 0


    def get_QueryComponents(self, page, tag):
        url = page[tag]
        query = urlparse(url).query
        if(query):
            return len(query.split('&'))
        else:
            return 0


    def get_QueryLength(self, page, tag):
        url = page[tag]
        query = urlparse(url).query
        if(query):
            return len(query)
        else:
            return 0


    def get_DomainInPaths(self, page, tag):
        url = page[tag]
        path = urlparse(url).path
        for ccTLD in dic_ccTLD:
            if path.find(ccTLD) > -1:
                return 1
        for TLD in dic_TLD_popular:
            if path.find(TLD) > -1:
                return 1
        return 0


    def get_DomainInSubdomains(self, page, tag):
        url = page[tag]
        subdomain = page['subdomain'].split('.')
        if(subdomain):
            for sub in subdomain:
                if('.'+sub) in dic_ccTLD:
                    return 1
                if('.'+sub) in dic_TLD_popular:
                    return 1
        return 0


    def get_PositionTLD(self, page, tag):
        url = page[tag]
        #subdomain = tldextract.extract(url).subdomain
        subdomain = page['subdomain']
        for tld in dic_TLD_popular:
            if subdomain.find(tld):
                return 1
        for tld in dic_TLD_popular:
            if url.count(tld) > 1:
                return 1
        return 0

    def get_checkKnowLTD(self, page, tag):
        url = page[tag]
        #suffix = tldextract.extract(url).suffix.split('.')
        suffix = page['suffix'].split('.')
        for suf in suffix:
            if ('.' + suf) in dic_TLD_popular:
                return 1
        return 0

    def get_DomainLengthURL(self, page, tag):
        #url = page[tag]
        #domain= tldextract.extract(url).domain
        return len(page['domain'])

    def get_SubdomainLengthURL(self, page, tag):
        url = page[tag]
        #subdomain = tldextract.extract(url).subdomain
        subdomain = page['subdomain']
        return len(subdomain)

    def get_PathLengthURL(self, page, tag):
        url = page[tag]
        path = urlparse(url).path
        return len(path)


    def get_HostnameLength(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #subdomain = tldextract.extract(url).subdomain
        domain = page['domain']
        subdomain = page['subdomain']
        if(subdomain[:4] == 'www.'):
            subdomain = subdomain[4:]
        host = subdomain + domain
        return len(host)

    def get_NumNumericChars_Path(self, page, tag):
        url = page[tag]
        path = urlparse(url).path
        count = 0
        for char in path:
            try:
                int(char)
                count += 1
            except:
                True
        return count
    
    def get_NumNumericChars_Subdomain(self, page, tag):
        url = page[tag]
        #subdomain = tldextract.extract(url).subdomain
        subdomain = page['subdomain'] 
        count = 0
        for char in subdomain:
            try:
                int(char)
                count += 1
            except:
                True
        return count

    def get_NumNumericChars_Domain(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        domain = page['domain']
        count = 0
        for char in domain:
            try:
                int(char)
                count += 1
            except:
                True
        return count


    def get_NumNumericChars_URL(self, page, tag):
        url = page[tag]
    
        count = 0
        for char in url:
            try:
                int(char)
                count += 1
            except:
                True
        return count

    def get_UsingIPAddress1(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        domain = page['domain']
        try:
            socket.inet_aton(domain)
            return 1
        except:
            return 0


    def get_NumHash_URL(self, page, tag):
        url = page[tag]
        return url.count('#')


    def get_NumAmpersand_URL(self, page, tag):
        url = page[tag]
        return url.count('&')


    def get_NumPercent_URL(self, page, tag):
        url = page[tag]
        return url.count('%')


    def get_NumDash_URL(self, page, tag):
        url = page[tag]
        return url.count('-')


    def get_NumUnderscore_URL(self, page, tag):
        url = page[tag]
        return url.count('_')


    def get_TildeSymbol_URL(self, page, tag):
        url = page[tag]
        if url.find('~') == -1:
            return 0
        else:
            return 1


    def get_checkHTTPSDomain_URL(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        domain = page['domain']
        if domain.lower().find('https') == -1:
            return 0
        return 1


    def get_numDots_SubDomain(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #subdomain = tldextract.extract(url).subdomain
        return (page['domain'] + page['subdomain']).count('.')


    def get_numDots_URL(self, page, tag):
        url = page[tag]
        return url.count('.')


    def get_NumDashDomain_URL(self, page, tag):
        url = page[tag]
        #domain = tldextract.extract(url).domain
        #subdomain = tldextract.extract(url).subdomain
        hostname = page['domain'] + page['subdomain']
        return hostname.count('-')


    def get_NumArroba_URL(self, page, tag):
        url = page[tag]
        return url.count('@')


    def get_checkRedirect_URL(self, page, tag):
        url = page[tag]
        number = url.count('//')
        if(number > 1):
            return 1
        return 0


    def get_PathLevel_URL(self, page, tag):
        url = page[tag]
        level = url.count('/') - 2
        if level <= 0:
            return 1
        return level


    def get_configFeatures_url(self, page, tag):
        url = page[tag]
        for key in self.config_url.keys():
            print(key, self.config_url[key](url))

    # url_tag == 'url1' | 'url2'
    def getAll_configFeatures_url(self, url_tag, path_time):
        df_header = pd.read_csv(self.header_path)
        df_dataset = pd.read_csv(self.output_csv_path)
        df_data_time = pd.read_csv(path_time)
        dataset_keys = list(df_dataset.keys())
        features_list = list(self.config_url.keys())

        for feature in features_list:
            if feature not in dataset_keys:
                dic = {'id': [], feature : []}
                dic_time = {'id':[], feature:[]}
                for id_ in df_dataset['id']:
                    index_id = df_dataset[df_dataset['id'] == id_].index[0]
                    page = {}
                    dic['id'].append(id_)
                    dic_time['id'].append(id_)
                    page['url1'] = df_header.iloc[index_id]['url1']
                    page['url2'] = df_header.iloc[index_id]['url2']
                    page['ip'] = df_header.iloc[index_id]['ip']
                    page['age'] = df_header.iloc[index_id]['age']
                    page['sslissuer'] = df_header.iloc[index_id]['sslissuer']
                    page['domain'] = tldextract.extract(page['url1']).domain
                    page['subdomain'] = tldextract.extract(page['url1']).subdomain
                    page['suffix'] = tldextract.extract(page['url1']).suffix
                    start = time.time()
                    dic[feature].append(self.config_url[feature](page, url_tag))
                    end = time.time()
                    dic_time[feature].append(end-start)

                df_time = pd.DataFrame.from_dict(dic_time)
                df_data_time = pd.merge(df_data_time, df_time, on='id')
                #model 3 feature
                df_feature = pd.DataFrame.from_dict(dic)
                df_dataset = pd.merge(df_dataset, df_feature, on='id')

        if 'RawWordCount' not in dataset_keys:
            dic = {'id':[], 'RawWordCount' :[], 'AvaregeWordLength' :[], 'LongestWordLength':[], 'ShortestWordLength':[],
                    'StandardDerivation' : [], 'AdjacentWordCount':[], 'AverageAdjacentWordLength':[], 'SeparatedWordCount':[],
                    'OtherWordsCount':[], 'RandomWordCount':[], 'KeywordCount':[], 'BrandNameCount':[], 'TargetBrandNameCount':[],
                    'TargetKeywordCount':[], 'SimilarBrandNameCount':[], 'SimilarKeywordCount':[], 'ConsecutiveCharacterRepeat':[]}
            dic_time = {'id':[], 'RawWordCount' :[], 'AvaregeWordLength' :[], 'LongestWordLength':[], 'ShortestWordLength':[],
                    'StandardDerivation' : [], 'AdjacentWordCount':[], 'AverageAdjacentWordLength':[], 'SeparatedWordCount':[],
                    'OtherWordsCount':[], 'RandomWordCount':[], 'KeywordCount':[], 'BrandNameCount':[], 'TargetBrandNameCount':[],
                    'TargetKeywordCount':[], 'SimilarBrandNameCount':[], 'SimilarKeywordCount':[], 'ConsecutiveCharacterRepeat':[]}
            for id_ in df_dataset['id']:
                page = {}
                index_id = df_dataset[df_dataset['id'] == id_].index[0]
                dic_time['id'].append(id_)
                dic['id'].append(id_)
                page['url1'] = df_header.iloc[index_id]['url1']
                page['url2'] = df_header.iloc[index_id]['url2']
                page['ip'] = df_header.iloc[index_id]['ip']
                start = time.time()
                data = self.preprocessingURL(page, url_tag)
                end = time.time()
                for key in data.keys():
                    dic[key].append(data[key])
                    dic_time[key].append(end-start)
            #for key in data.keys():
                #print(key, len(dic[key]))

            df_time = pd.DataFrame.from_dict(dic_time)
            df_data_time = pd.merge(df_data_time, df_time, on='id')

            df_feature = pd.DataFrame.from_dict(dic)
            df_dataset = pd.merge(df_dataset, df_feature, on='id')

        return df_dataset, df_data_time


    def getAll_configFeatures_url2(self, url_tag, path_time):
        df_header = pd.read_csv(self.header_path)
        df_dataset = pd.read_csv(self.output_csv_path)
        df_data_time = pd.read_csv(path_time)
        dataset_keys = list(df_dataset.keys())
        features_list = list(self.config_url.keys())

        counter = 0
        dic = {'id': []}
        dic_time = {'id':[]}
        for feature in features_list:
            if feature not in dataset_keys:
                dic[feature] = []
                dic_time[feature] = []

        for id_ in df_dataset['id']:
            print("Page: ", counter)
            counter += 1
            index_id = df_dataset[df_dataset['id'] == id_].index[0]
            page = {}
            dic['id'].append(id_)
            dic_time['id'].append(id_)
            page['url1'] = df_header.iloc[index_id]['url1']
            page['url2'] = df_header.iloc[index_id]['url2']
            page['ip'] = df_header.iloc[index_id]['ip']
            page['age'] = df_header.iloc[index_id]['age']
            page['sslissuer'] = df_header.iloc[index_id]['sslissuer']
            page['domain'] = tldextract.extract(page['url1']).domain
            page['subdomain'] = tldextract.extract(page['url1']).subdomain
            page['suffix'] = tldextract.extract(page['url1']).suffix
            #page['whois'] = whois.whois(page['domain'] + '.'+ page['suffix'])

            for feature in features_list:
                if feature not in dataset_keys:
                    start = time.time()
                    dic[feature].append(self.config_url[feature](page, url_tag))
                    end = time.time()
                    dic_time[feature].append(end-start)

        df_time = pd.DataFrame.from_dict(dic_time)
        df_data_time = pd.merge(df_data_time, df_time, on='id')
        #model 3 feature
        df_feature = pd.DataFrame.from_dict(dic)
        df_dataset = pd.merge(df_dataset, df_feature, on='id')

        if 'RawWordCount' not in dataset_keys:
            dic = {'id':[], 'RawWordCount' :[], 'AvaregeWordLength' :[], 'LongestWordLength':[], 'ShortestWordLength':[],
                    'StandardDerivation' : [], 'AdjacentWordCount':[], 'AverageAdjacentWordLength':[], 'SeparatedWordCount':[],
                    'OtherWordsCount':[], 'RandomWordCount':[], 'KeywordCount':[], 'BrandNameCount':[], 'TargetBrandNameCount':[],
                    'TargetKeywordCount':[], 'SimilarBrandNameCount':[], 'SimilarKeywordCount':[], 'ConsecutiveCharacterRepeat':[]}
            dic_time = {'id':[], 'RawWordCount' :[], 'AvaregeWordLength' :[], 'LongestWordLength':[], 'ShortestWordLength':[],
                    'StandardDerivation' : [], 'AdjacentWordCount':[], 'AverageAdjacentWordLength':[], 'SeparatedWordCount':[],
                    'OtherWordsCount':[], 'RandomWordCount':[], 'KeywordCount':[], 'BrandNameCount':[], 'TargetBrandNameCount':[],
                    'TargetKeywordCount':[], 'SimilarBrandNameCount':[], 'SimilarKeywordCount':[], 'ConsecutiveCharacterRepeat':[]}
            for id_ in df_dataset['id']:
                page = {}
                index_id = df_dataset[df_dataset['id'] == id_].index[0]
                dic_time['id'].append(id_)
                dic['id'].append(id_)
                page['url1'] = df_header.iloc[index_id]['url1']
                page['url2'] = df_header.iloc[index_id]['url2']
                page['ip'] = df_header.iloc[index_id]['ip']
                start = time.time()
                data = self.preprocessingURL(page, url_tag)
                end = time.time()
                for key in data.keys():
                    dic[key].append(data[key])
                    dic_time[key].append(end-start)
            #for key in data.keys():
                #print(key, len(dic[key]))

            df_time = pd.DataFrame.from_dict(dic_time)
            df_data_time = pd.merge(df_data_time, df_time, on='id')

            df_feature = pd.DataFrame.from_dict(dic)
            df_dataset = pd.merge(df_dataset, df_feature, on='id')

        return df_dataset, df_data_time

    def get_simplefeatures(self, dic_html):
        dic = {}
        page = {}
        page['url1'] = dic_html['url']
        page['ip'] = dic_html['ip']
        page['html'] = dic_html['html']
        page['domain'] = tldextract.extract(page['url1']).domain
        page['subdomain'] = tldextract.extract(page['url1']).subdomain
        page['suffix'] = tldextract.extract(page['url1']).suffix
        page['whois'] = whois.whois(page['domain'] + '.'+ page['suffix'])
        for feature in self.config_url.keys():
            dic[feature] = self.config_url[feature](page, 'url1')

        # other
        data = self.preprocessingURL(page, 'url1')
        for key in data.keys():
                    dic[key] = data[key]
        return dic