from preprocess.URLModel import Pre_processing_URL
from preprocess.HTMLModel import Pre_processing_HTML
from preprocess.EXTERNModel import Pre_processing_EXTERN
from preprocess.features_config import ALL_LIST
from sklearn.ensemble import RandomForestClassifier
from model.abc_positions import abc_positions
import joblib
import pandas as pd

class Controller():
    def __init__(self):
        self.model = joblib.load('model/abc')    

    
    def get_features_fromlist(self, features_list, page_list):

        pre_html = Pre_processing_HTML() 
        set_list = pre_html.set_featureslist(features_list)
        if set_list != []:
            df_html = pre_html.get_dffromlist(page_list)

        pre_url = Pre_processing_URL()
        set_list = pre_url.set_featureslist(features_list)
        if set_list != []:
            df_url = pre_url.get_dffromlist(page_list)

        pre_extern = Pre_processing_EXTERN()
        set_list = pre_extern.set_featureslist(features_list)
        if set_list != []:
            df_extern = pre_extern.get_dffromlist(page_list)
        df_final = pd.merge(df_html, df_url, on = ['id', 'class'])
        df_final = pd.merge(df_final, df_extern, on = ['id', 'class'])
        return df_final

    def predict(self, dic_html):
        pre_url = Pre_processing_URL()
        dic = pre_url.get_simplefeatures(dic_html)
        pre_html = Pre_processing_HTML()
        dic.update(pre_html.get_simplefeatures(dic_html))
        
        
        instance = []
        for i in range(len(abc_positions)):
                instance.append(dic[abc_positions[i]][0])    
        return self.model.predict([instance])[0]



control = Controller()
#features_list = ['UsingIPAddress1', 'URLlengthRule1', 'checkArrobaURL', 'checkDashDomain', 'checkSubDomainMulSubDomain', 'SSLFinal_state2', 'ForeignhyperlinksRule1', 'URLofAnchorRule1', 'ServerFormHandler', 'AbnormalURL', 'statusBarCost', 'DisablingRightClick', 'PopUpWindow', 'AgeOfDomain', 'DNSRecord', 'checkAlexa', 'numDotsURL', 'NumDotSubDomain', 'pathLevelURL', 'URLlength', 'NumDashURL', 'NumDashDomain', 'checkTildeSymbolURL', 'NumUnderscoreURL', 'NumPercentURL', 'QueryComponents', 'NumAmpersandURL', 'NumHashURL', 'NumNumericCharsURL', 'NoHTTPS', 'RandomString', 'DomainInSubdomains', 'DomainInPaths', 'checkHTTPSDomainURL', 'HostnameLenth', 'PathLength', 'QueryLength', 'checkRedirectURL', 'NumSensitiveWords', 'EmbeddedBrandName', 'Foreignhyperlinks', 'PctExtResourceUrls', 'FaviconD', 'InsecureForm', 'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction', 'URLofAnchorCat', 'FrequentDomainNameMismatch', 'SubmittingEmailTo', 'IframeOrFrame', 'checkTitle', 'ImagesOnlyInForm', 'LinksMetaScriptRule1', 'RawWordCount', 'BrandNameDomain', 'AvaregeWordLength', 'LongestWordLength', 'ShortestWordLength', 'StandardDerivation', 'AdjacentWordCount', 'AverageAdjacentWordLength', 'SeparatedWordCount', 'KeywordCount', 'BrandNameCount', 'SimilarKeywordCount', 'SimilarBrandNameCount', 'RandomWordCount', 'TargetBrandNameCount', 'OtherWordsCount', 'NumNumericChars_Subdomain', 'NumNumericChars_Domain', 'NumNumericChars_Path', 'RandomDomain', 'DomainLength', 'SubdomainLength', 'KnowLTD', 'checkWWW', 'checkCOM', 'numArroba', 'numInterrogation', 'numBar', 'numEqual', 'ConsecutiveCharacterRepeat', 'numDots_URLRule4', 'SpecialSymbol4', 'URLlengthRule4', 'SuspiciousInURL', 'get_PositionTLD', 'httpCountInURL', 'BrandNameURL', 'CheckDataURI', 'FakeLoginForm', 'Numberofwebpages', 'Nohyperlinkfeature', 'ForeignhyperlinksRule4', 'URLofAnchorRule4', 'Copied_CSS', 'Copyrightfeatures', 'IdentityKeywords']
page_list = []
df1 = pd.read_csv('final_test_html.csv')
for i in range(len(df1)):
    dic = {}
    dic['url'] = df1.iloc[i]['url1']
    dic['ip'] = df1.iloc[i]['ip']
    dic['html'] = df1.iloc[i]['html']
    dic['id'] = df1.iloc[i]['id']
    dic['class'] = df1.iloc[i]['class']
    page_list.append(dic)

df = control.get_features_fromlist(ALL_LIST, page_list)
df.to_csv('DF_ALL.csv', index = False)