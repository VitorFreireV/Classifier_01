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
from progress.bar import IncrementalBar
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
                           'checkHTTPSDomainURL': self.get_checkHTTPSDomain_URL,#1.12, 2.20
                           'StatisticalReports': self.get_StatisticalReports, # 1.29
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
                          }



    def set_featureslist(self, features_list):
        config_list = {}
        for key in self.config_url.keys():
            if key in features_list:
                config_list[key] = self.config_url[key]
        self.config_url = config_list
        return list(config_list.keys())

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


    def get_numArroba(self, page, tag):
        return page[tag].count('@')


    def get_numEqual(self, page, tag):
        return page[tag].count('=')


    def get_numBar(self, page, tag):
        return page[tag].count('/')


    def get_numInterrogation(self, page, tag):
        return page[tag].count('?')    


    def get_checkCOM(self, page, tag):
        if page['subdomain'].find('.com') > -1:
            return 1
        if page['domain'].find('.com') > -1:
            return 1
        return 0


    def get_checkWWW(self, page, tag):
        subdomain = page['subdomain']
        domain = page['domain']
        if subdomain[:3] == 'www':
            subdomain = subdomain[3:]
        if subdomain.find('www.') > -1:
            return 1
        if domain.find('www') > -1:
            return 1
        return 0


    def get_RandomDomain(self, page, tag):
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


    def get_simplefeatures(self, dic_html):
        dic = {}
        page = {}
        page['url1'] = dic_html['url']
        page['ip'] = dic_html['ip']
        page['html'] = dic_html['html']
        page['domain'] = tldextract.extract(page['url1']).domain
        page['subdomain'] = tldextract.extract(page['url1']).subdomain
        page['suffix'] = tldextract.extract(page['url1']).suffix
        #page['whois'] = whois.whois(page['domain'] + '.'+ page['suffix'])
        for feature in self.config_url.keys():
            dic[feature] = [self.config_url[feature](page, 'url1')]

        # other
        data = self.preprocessingURL(page, 'url1')
        for key in data.keys():
                #if key in features_list:
                dic[key] = [data[key]]
        return dic


    def get_dffromlist(self, list_html):
        bar = IncrementalBar('URL Features Progress:', max = len(list_html))
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