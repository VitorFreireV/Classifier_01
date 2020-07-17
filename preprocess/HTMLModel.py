import pandas as pd
from preprocess.knowledgebase import *
import tldextract
import re
import validators
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from yurl import URL
from urlextract import URLExtract
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
import numpy as np
#from dic_freq_domain import dic_freq_domain
import operator
from urllib.parse import urlparse, urlencode
from nltk.corpus import stopwords
from datauri import DataURI
import requests
import time
import json
from progress.bar import IncrementalBar

class Pre_processing_HTML:
    def __init__(self, header_path = '', output_csv_path = ''):
        self.header_path = header_path
        self.output_csv_path = output_csv_path
        self.count =0
        self.config_html = {
                            'ForeignhyperlinksRule1':self.get_ForeignhyperlinksRule1,#1.13
                            'URLofAnchorRule1': self.get_URLofAnchorRule1,#1.14
                            'LinksMetaScriptRule1':self.get_LinksMetaScriptRule1,#1.15
                            'FaviconD': self.get_FaviconD, #1.10, 2.29
                            'statusBarCost': self.get_statusBarCost, #1.20. 2.36
                            'SubmittingEmailTo': self.get_SubmittingEmailTo, #1.17, # 2.39
                            'DisablingRightClick': self.get_DisablingRightClick, #1.21, 2.37
                            'IFrameRedFrameBorder' : self.get_IFrameRedFrameBorder, # 1.23
                            #'NumberRedirect' : self.get_NumberRedirect,
                            #'numberOfLinksPointPage': self.get_numberOfLinksPointPage, #1.28
                            'ServerFormHandler':self.get_ServerFormHandler,

                            'EmbeddedBrandName':self.get_EmbeddedBrandName, #2.26
                            'Foreignhyperlinks':self.get_Foreignhyperlinks, # 2.28
                            'URLofAnchorCat': self.get_URLofAnchorCategoric, #2.34
                            'InsecureForm':self.get_InsecureForm, #2.30
                            'RelativeFormAction':self.get_RelativeFormAction, #2.31
                            'ExtFormAction':self.get_ExtFormAction, #2.32
                            'AbnormalFormAction':self.get_AbnormalFormAction, #2.33
                            'FrequentDomainNameMismatch':self.get_FrequentDomainNameMismatch, #2.35
                            'PopUpWindow': self.get_PopUpWindow, # 2.38
                            'ImagesOnlyInForm': self.get_ImagesOnlyInForm, #2.42
                            'PctExtResourceUrls' : self.get_URLofAnchorCategoric,
                            'IframeOrFrame' : self.get_IframeOrFrame,

                            'LinksMetaScript': self.get_LinksMetaScript,
                            'checkTitle':self.get_checkTitle,
                            'Numberofwebpages':self.get_Numberofwebpages, #4.10
                            'FakeLoginForm':self.get_FakeLoginForm,
                            'ForeignhyperlinksRule4': self.get_ForeignhyperlinksRule4,
                            'Nohyperlinkfeature':self.get_Nohyperlinkfeature, #4.11
                            'Copied_CSS':self.get_Copied_CSS,
                            'Copyrightfeatures':self.get_Copyrightfeatures,
                            'IdentityKeywords': self.get_IdentityKeywords,
                            'URLofAnchorRule4':self.get_URLofAnchorRule4,
                            #'ErrorinHyperlinks':self.get_ErrorinHyperlinks,
                            #'ErrorinHyperlinksRule4':self.get_ErrorinHyperlinksRule4,
                            #'HyperlinksRedirections':self.get_HyperlinksRedirections,
                            #'HyperlinksRedirectionsRule4':self.get_HyperlinksRedirectionsRule4,
                            'CheckDataURI':self.get_CheckDataURI,
                            'IFrameExternalSRC':self. get_IFrameExternalSRC
                           }
    # Função utilitaria para encontrar urls
    # Implementação de verificar sufixo para evitar pegar classes do codigo html como url
    def find_urls(self, text):
        extractor = URLExtract()
        urls_candidates = extractor.find_urls(text)
        urls = []
        for url in urls_candidates:
            if(url[:4] == 'http'):
                urls.append(url)
            else:
                sufix = tldextract.extract(url).suffix
                for ccTLD in dic_TLD_popular:
                    if sufix.find(ccTLD) > -1:
                        urls.append(url)
                        break
        return urls    

    
    def find_numberHyperlinks(self, page):
        domain = tldextract.extract(page['url']).domain
        soup = page['soup']
        count = 0
        count_all = 0
        hyperlink_list = []
        for img in soup.findAll('img'):
            src = img.get('src')
            if(src != None):
                hyperlink_list.append(src)
                count_all +=1
                if domain != tldextract.extract(src).domain and not URL(src).is_relative():
                    count += 1
                
        for script in soup.findAll('script'):
            src = script.get('src')
            if(src != None):
                hyperlink_list.append(src)
                count_all +=1
                if domain != tldextract.extract(src).domain and not URL(src).is_relative():
                    count += 1
        
        for frame in soup.findAll('frame'):
            src = frame.get('src')
            if(src != None):
                hyperlink_list.append(src)
                count_all +=1
                if domain != tldextract.extract(src).domain and not URL(src).is_relative():
                    count += 1

        for inpu in soup.findAll('input'):
            src = inpu.get('src')
            if(src != None):
                hyperlink_list.append(src)
                count_all +=1
                if domain != tldextract.extract(src).domain and not URL(src).is_relative():
                    count += 1

        for link in soup.findAll('link'):
            href = link.get('href') 
            if(href != None):
                hyperlink_list.append(href)
                count_all +=1
                if domain != tldextract.extract(href).domain and not URL(href).is_relative() :
                    count += 1    

        for a in soup.findAll('a'):
            href = a.get('href')
            if(href != None):
                hyperlink_list.append(href)
                count_all +=1
                if domain != tldextract.extract(href).domain and not URL(href).is_relative():
                    count += 1    
        return count, count_all, hyperlink_list

    # Retorna o dominio mais frequente no texto
    def find_EmbeddedBrandName(self, text):
        urls = self.find_urls(text)
        domain_dic = {}
        for url in urls:
            domain = tldextract.extract(url).domain
            if domain not in domain_dic.keys():
                domain_dic[domain] = 1
            else:
                domain_dic[domain] += 1
        if domain_dic:
            sortedDict = sorted(domain_dic.items(), key=operator.itemgetter(1))
            return sortedDict[0][0]
        return -1

    def get_NumberRedirect(self, page):
        har = page['har']
        count = 0
        for data in har['log']['entries']:
            if data['response']['redirectURL'] != '':
                count+1
        return count

    def get_ErrorinHyperlinksRule4(self, page):
        percent = self.get_ErrorinHyperlinks(page)
        if percent > 0.3:
            return 1
        else:
            return 0

    def get_IframeOrFrame(self, page):
        soup = page['soup']
        iframes = soup.findAll('iframe')
        frames = soup.findAll('frames')
        if len(iframes)>0 or len(frames)>0:
            return 1
        else:
            return 0

    def get_HyperlinksRedirectionsRule4(self, page):
        percent = self.get_HyperlinksRedirections(page)
        if percent > 0.3:
            return 1
        else:
            return 0

    def get_HyperlinksRedirections(self, page):
        count, count_all, list_links = self.find_numberHyperlinks(page)
        count = 0
        count_all = 0
        for link in list_links:
            if validators.url(link):
                count_all += 1
                try:
                    req = requests.head(link, verify = False)
                    if req.status_code == 301 or req.status_code == 302:
                        count += 1
                except:
                    count_all -= 1
        if count_all == 0:
            return 0
        else:
            return float(count) / float(count_all)

    def get_ErrorinHyperlinks(self, page):
        count, count_all, list_links = self.find_numberHyperlinks(page)
        count = 0
        count_all = 0
        for link in list_links:
            if validators.url(link):
                count_all += 1
                try:
                    if link[:4] != 'http':
                        link = 'http://' + link
                    req = requests.head(link, verify = False)
                    if req.status_code == 404 or req.status_code == 403:
                        count += 1
                except:
                    True
        if count_all == 0:
            return 0
        else:
            return float(count) / float(count_all)


    def get_IdentityKeywords(self, page):
        soup = page['soup']
        domain = tldextract.extract(page['url']).domain
        doc = ''
        for m in soup.findAll('meta'):
            doc += str(m) + '\n'
        for  t in soup.findAll('title'):
            doc += str(t.text) + '\n'
        text = soup.text
        stop_words_web = ['www', 'url', 'src', 'javascript', 'meta', 'locale', 'http', 'https', 'name', 'content', 'data', 'property']
        stop_words = stopwords.words('portuguese') + stopwords.words('english') + stop_words_web

        if text:
            if doc:
                corpus = [doc, text]
            else:
                corpus = [text]
        elif doc:
            corpus = [doc]
        else:
            return -1
        if(corpus): 
            try:
                vectorizer = TfidfVectorizer(max_features = 30, stop_words = stop_words)
                X = vectorizer.fit_transform(corpus)
                keywords = vectorizer.get_feature_names()
                for key in keywords:
                    if domain.lower().find(key.lower()) > -1:
                        return 0
            except:
                return -2
        return 1

    def get_ImagesOnlyInForm(self, page):
        soup = page['soup']
        for form in soup.findAll('form'):
            if form.text != '':
                return 0
        return 1
    

    def get_ServerFormHandler(self, page):
        soup = page['soup']
        domain = tldextract.extract(page['url']).domain

        for form in soup.findAll('form'):
            action = form.get('action')
            if(action != None):
                if action == 'about:blank' or action == '':
                    return 2
                elif URL(action).is_relative() == False and domain != tldextract.extract(action).domain:
                    return 1
        return 0

    def get_PopUpWindow(self, page):
        html = page['html']
        if html.find('window.open(') > -1:
            return 1
        else:
            return 0


    def get_EmbeddedBrandName(self, page):
        url = page['url']
        subdomain = tldextract.extract(url).subdomain
        path = urlparse(url).path
        brandname = self.find_EmbeddedBrandName(page['html'])
        if brandname != -1:
            if subdomain.find(brandname) > -1 or path.find(brandname) > -1:
                return 1
        return 0

    def get_numberOfLinksPointPage(self, page):
        url = page['url']
        domain = tldextract.extract(url).domain
        if domain in dic_freq_domain.keys():
            if dic_freq_domain[domain] == 0:
                return 1
            elif dic_freq_domain[domain] >= 2:
                return 1
            else:
                return 0
        else:
            return 2

    def get_IFrameRedFrameBorder(self, page):
        soup = page['soup']
        url = page['url']
        allIframe = soup.findAll('iframe')
        domain = tldextract.extract(url).domain

        for iframe in allIframe:
            att = iframe.get('frameBorder')
            if(att != None):
                if att == 0:
                    return 1              
        return 0

    def get_DisablingRightClick(self, page):
        html = page['html']
        x = re.search(r"event.button *== *2", html)
        if(x):
            return 1
        return 0 

    def get_SubmittingEmailTo(self, page):
        soup = page['soup']
        url = page['url']
        #domain = tldextract.extract(url).domain

        for form in soup.findAll('form'):
            href = form.get('action')
            if(href != None):
                if href.lower().find('mailto:') > -1:
                    return 1
        return 0

    def get_FrequentDomainNameMismatch(self, page):
        domain = tldextract.extract(page['url']).domain
        html = page['html']
        urls = self.find_urls(html)
        dic_freq = {}
        for url in urls:
            domain_candiate = tldextract.extract(url).domain
            if domain_candiate in dic_freq.keys():
                dic_freq[domain_candiate] += 1
            else:
                dic_freq[domain_candiate] = 1
        domains = list(dic_freq.keys())
        values = list(dic_freq.values())
        if values:
            top_domain = domains[np.argmax(np.array(values))]
            if top_domain.lower() == domain.lower():
                return 1
        return 0
        

    def get_ExtFormAction(self, page):
        soup = page['soup']
        url = page['url']
        domain = tldextract.extract(url).domain

        for form in soup.findAll('form'):
            href = form.get('action')
            if(href != None):
                if(URL(href).is_relative()):
                    return 0
                domain_href = tldextract.extract(href).domain
                if domain != domain_href:
                    return 1

        return 0

    def get_AbnormalFormAction(self, page):
        soup = page['soup']
        url = page['url']
        domain = tldextract.extract(url).domain

        for form in soup.findAll('form'):
            href = form.get('action')
            if(href != None):
                if href == '#' or href.lower() == 'javascript:void(0)' or href.lower() == 'javascript: true'  or href.lower() == 'about: blank':
                    return 1
        return 0
        
    def get_RelativeFormAction(self, page):
        soup = page['soup']
        url = page['url']
        domain = tldextract.extract(url).domain

        for form in soup.findAll('form'):
            href = form.get('action')
            if(href != None):
                if(URL(href).is_relative()):
                    return 1
        return 0

    def get_InsecureForm(self, page):
            soup = page['soup']
            url = page['url']
            domain = tldextract.extract(url).domain

            for form in soup.findAll('form'):
                href = form.get('action')
                if(href != None):
                    if(href[:5].lower() != 'https'):
                        return 1
            return 0

    def get_statusBarCost(self, page):
        soup = page['soup']
        all_ = soup.findAll(onmouseover = True)
        if len(all_) >= 1:
            return 1
        return 0

    def get_LinksMetaScriptRule1(self, page):
        percent = self.get_LinksMetaScript(page)
        if percent < 0.17:
            return 0
        elif percent <= 0.82:
            return 1
        else:
            return 2

    def get_URLofAnchorRule4(self,page):
        percent = self.get_URLofAnchorCategoric(page)
        if percent > 0.34:
            return 1
        else:
            return 0


    def get_URLofAnchorRule1(self,page):
        percent = self.get_URLofAnchorCategoric(page)
        if percent < 0.31:
            return 0
        elif percent <= 0.67:
            return 1
        else:
            return 2

    def get_ForeignhyperlinksRule1(self, page):
        percent = self.get_Foreignhyperlinks(page)
        if percent < 0.20:
            return 0
        elif percent <= 0.50:
            return 1
        else:
            return 2
    
    def get_ForeignhyperlinksRule4(self, page):
        percent = self.get_Foreignhyperlinks(page)
        if percent <= 0.5:
            return 0
        else:
            return 1

    def get_Copyrightfeatures(self, page):
        soup = page['soup']
        url = page['url']
        copyrightTexts = ''
        domain = tldextract.extract(url).domain
        for tag in soup.findAll(text=re.compile(r'© | & copy | copyright | all right reserved ;')):
            copyrightTexts = tag.parent.text
        if copyrightTexts:
            try:
                vectorizer = CountVectorizer()
                vectorizer.fit([copyrightTexts])
                words = vectorizer.get_feature_names()
                for word in words:
                    if word.lower() == domain.lower():
                        return 0
            except:
                if copyrightTexts.lower().find(domain) > -1:
                    return 0
        return 1


    def get_Copied_CSS(self, page):
        soup = page['soup']
        domain = tldextract.extract(page['url']).domain

        styles = soup.findAll("link", rel = "stylesheet")
        for style in styles:
            href = style.get('href')
            if(href != None):
                if(URL(href).is_relative()):
                    return 0

                domain_candidate = tldextract.extract(href).domain
                if domain != domain_candidate:
                    return 1
        return 0

    def get_Foreignhyperlinks(self, page):
        count, count_all, _ = self.find_numberHyperlinks(page)
        if count == 0:
            return 0
        else:
            return float(count)/float(count_all)

    def get_Nohyperlinkfeature(self, page):
        count, count_all, _ = self.find_numberHyperlinks(page)
        if count_all > 0:
            return 1
        else:
            return 0

    def get_FakeLoginForm(self, page):
        soup = page['soup']
        url = page['url']
        domain = tldextract.extract(url).domain

        for form in soup.findAll('form'):
            href = form.get('action')
            if(href != None):

                if href == '#' or href.lower() == 'javascript:void(0)' or href.lower() == '#skip'  or href.lower() == '#content':
                    return 1
                if href[-4:] == '.php':
                    return 1
                if(URL(href).is_relative()):
                    return 0
                domain_href = tldextract.extract(href).domain
                if domain != domain_href:
                    return 1

        return 0

    def get_CheckDataURI(self, page):
        soup = page['soup']
        for script in soup.findAll('script'):
            src = script.get('src')
            if(src != None):
                try:
                    uri = DataURI(src)
                    return 1
                except:
                    True
        for img in soup.findAll('img'):
            src = img.get('src')
            if(src != None):
                try:
                    uri = DataURI(src)
                    return 1
                except:
                    True
        return 0


    def get_Numberofwebpages(self, page):
        cont, cont_all, _ = self.find_numberHyperlinks(page)
        return cont_all


    def get_checkTitle(self, page):
        soup = page['soup']
        title = soup.findAll('title')
        for t in title:
            if t:
                if t.text != '':
                    return 1
                else:
                    return 0
        return 1


    def get_IFrameExternalSRC(self, page):
        soup = page['soup']
        url = page['url']
        allIframe = soup.findAll('iframe')
        domain = tldextract.extract(url).domain

        for iframe in allIframe:
            href = iframe.get('src')
            if(href != None):
                if(validators.url(href)):
                    domain_frame = tldextract.extract(href).domain
                    if(domain_frame != domain):
                        return 1
                    else:
                        return 0
                if(URL(href).is_relative()):
                    return 0
        return 0

    def get_FaviconD(self, page):
        soup = page['soup']
        url = page['url']
        icon_link = soup.find("link", rel = "shortcut icon")

        if not icon_link:
            icon_link = soup.find("link", rel = "icon")

        if(icon_link):
            if(icon_link.get('href')!= None):
                if URL(icon_link['href']).is_relative():
                    return 0

                domain_url = tldextract.extract(url).domain
                domain_favicon = tldextract.extract(icon_link['href']).domain

                if(domain_url != domain_favicon):
                    return 1
            #return 0
        return 0

    def get_URLofAnchorCategoric(self,page):
        soup = page['soup']
        url = page['url']
        all_a = soup.findAll('a')
        domain_url = tldextract.extract(url).domain

        count_all_a = 0
        count_select_a = 0

        for a in all_a:
            href = a.get('href')
            if(href != None):
                count_all_a += 1
                href.replace(' ','')
                if(validators.url(href)):
                    domain_a = tldextract.extract(href).domain
                    if(domain_a != domain_url):
                        count_select_a += 1
                elif(href == '#' or href.lower() == '#content'
                     or href.lower() == '#skip' or href.lower() == 'javascript::void(0)'):
                    count_select_a += 1

        if count_all_a == 0:
            return 0

        percent = float(count_select_a)/float(count_all_a)
        #print("Percent URL Anchor: ", percent)
        return percent

    def get_LinksMetaScript(self, page):
        soup = page['soup']
        url = page['url']
        count_select = 0
        count_all = 0
        allLinks = soup.findAll('link')
        domain_url = tldextract.extract(url).domain

        for link in allLinks:
            href = link.get('href')
            if(href != None):
                count_all += 1
                domain_link = tldextract.extract(href).domain
                if domain_link != domain_url:
                    count_select += 1


        allMeta = soup.findAll('meta')
        for meta in allMeta:
            href = meta.get('content')
            if(href != None):
                # verifica se é uma url
                if(validators.url(href)):
                    count_all += 1
                    domain_meta = tldextract.extract(href).domain
                    if domain_meta != domain_url:
                        count_select += 1

                # verifica se é uma url relativa
                if(URL(href).is_relative()):
                    count_all += 1

        allScript = soup.findAll('script')
        for script in allScript:
            href = script.get('src')
            if(href != None):
                if(validators.url(href)):
                    count_all += 1
                    domain_script = tldextract.extract(href).domain
                    if domain_script != domain_url:
                        count_select += 1
                if(URL(href).is_relative()):
                    count_all += 1

        if(count_all == 0):
            return 0
        percent = float(count_select) / float(count_all)

        #print('Percent MetaLinkScript: ', percent)
        return percent
        # Ajustar regra aos dados
        if percent < 0.17:
            return 0
        elif percent <= 0.81:
            return 1
        else:
            return 2

    def getAll_configFeatures_html(self, path_time):
        df_header = pd.read_csv(self.header_path)
        df_dataset = pd.read_csv(self.output_csv_path)
        df_data_time = pd.read_csv(path_time)
        dataset_keys = list(df_dataset.keys())
        features_list = list(self.config_html.keys())

        for feature in features_list:
            if feature not in dataset_keys:
                dic = {'id': [], feature : []}
                dic_time = {'id':[], feature:[]}
                for id_ in df_dataset['id']:
                    index_id = df_dataset[df_dataset['id'] == id_].index[0]
                    page = {}
                    dic['id'].append(id_)
                    dic_time['id'].append(id_)

                    #url = df_header.iloc[id_]['url2']
                    page['url'] = df_header.iloc[index_id]['url2']
                    page['ip'] = df_header.iloc[index_id]['ip']
                    if df_header.iloc[index_id]['class']== 0:
                        file = open('legitime/html/'+str(id_) + '.html', 'r')
                    else:
                        file = open('phish/html/'+str(id_) + '.html', 'r')
                    html = file.read()
                    soup = BeautifulSoup(html, 'html.parser')
                    page['html'] = html
                    page['soup'] = soup
                    start = time.time()
                    dic[feature].append(self.config_html[feature](page))
                    end = time.time()
                    dic_time[feature].append(end-start)

                df_time = pd.DataFrame.from_dict(dic_time)
                df_data_time = pd.merge(df_data_time, df_time, on='id')

                df_feature = pd.DataFrame.from_dict(dic)
                df_dataset = pd.merge(df_dataset, df_feature, on='id')
        return df_dataset, df_data_time

    def getAll_configFeatures_html2(self, path_time):
        df_header = pd.read_csv(self.header_path)
        df_dataset = pd.read_csv(self.output_csv_path)
        df_data_time = pd.read_csv(path_time)
        dataset_keys = list(df_dataset.keys())
        features_list = list(self.config_html.keys())

        counter = 0
        dic = {'id': []}
        dic_time = {'id':[]}
        for feature in features_list:
            if feature not in dataset_keys:
                dic[feature] = []
                dic_time[feature] = []

        bar = IncrementalBar('Countdown', max = len(df_dataset))
        for id_ in df_dataset['id']:  
            bar.next()
            print("Page: ", counter)
            counter += 1
            index_id = df_dataset[df_dataset['id'] == id_].index[0]
            page = {}
            dic['id'].append(id_)
            dic_time['id'].append(id_)

            #url = df_header.iloc[id_]['url2']
            page['url'] = df_header.iloc[index_id]['url2']
            page['ip'] = df_header.iloc[index_id]['ip']
            file = open('legitme_other/html/'+str(id_) + '.html', 'r')
            filehar = open('legitme_other/har/'+str(id_) + '.json', 'r')
            '''
            if df_header.iloc[index_id]['class']== 0:
                file = open('legitime/html/'+str(id_) + '.html', 'r')
                filehar = open('legitime/har/'+str(id_) + '.json', 'r')

            else:
                file = open('phish/html/'+str(id_) + '.html', 'r')
                filehar = open('phish/har/'+str(id_) + '.json', 'r')
            '''

            html = file.read()
            soup = BeautifulSoup(html, 'html.parser')
            page['html'] = html
            page['soup'] = soup
            page['har'] = json.load(filehar)

            for feature in features_list:
                if feature not in dataset_keys:
                    start = time.time()
                    dic[feature].append(self.config_html[feature](page))
                    end = time.time()
                    dic_time[feature].append(end-start)

        df_time = pd.DataFrame.from_dict(dic_time)
        df_data_time = pd.merge(df_data_time, df_time, on='id')

        df_feature = pd.DataFrame.from_dict(dic)
        df_dataset = pd.merge(df_dataset, df_feature, on='id')
        bar.finish()
        return df_dataset, df_data_time

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
        for feature in self.config_html.keys():
            dic[feature] = self.config_html[feature](page)

        return dic