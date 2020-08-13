from preprocess.URLModel import Pre_processing_URL
from preprocess.HTMLModel import Pre_processing_HTML
from preprocess.EXTERNModel import Pre_processing_EXTERN
from preprocess.features_config import ALL_LIST, URL_LIST, HTML_LIST
from sklearn.ensemble import RandomForestClassifier
from model.abc_positions import abc_positions
import joblib
import pandas as pd

class Controller():
    def __init__(self):
        self.model = joblib.load('model/abc')    

    
    def get_features_fromlist(self, features_list, page_list):
        
        # Init DF_final
        df_dic = {'id':[], 'class':[]}
        for page in page_list:
            df_dic['id'].append(page['id'])
            df_dic['class'].append(page['class'])
        df_final = pd.DataFrame.from_dict(df_dic)

        # get features
        pre_html = Pre_processing_HTML() 
        set_list = pre_html.set_featureslist(features_list)
        if set_list != []:
            df_html = pre_html.get_dffromlist(page_list)
            df_final = pd.merge(df_final, df_html, on = ['id', 'class'])

        pre_url = Pre_processing_URL()
        set_list = pre_url.set_featureslist(features_list)
        if set_list != []:
            df_url = pre_url.get_dffromlist(page_list)
            df_final = pd.merge(df_final, df_url, on = ['id', 'class'])

        pre_extern = Pre_processing_EXTERN()
        set_list = pre_extern.set_featureslist(features_list)
        if set_list != []:
            df_extern = pre_extern.get_dffromlist(page_list)
            df_final = pd.merge(df_final, df_extern, on = ['id', 'class'])

        return df_final


    def predict(self, dic_html):

        pre_url = Pre_processing_URL()
        set_list = pre_url.set_featureslist(abc_positions)
        if set_list != []:
            dic = pre_url.get_simplefeatures(dic_html)

        pre_html = Pre_processing_HTML()
        set_list = pre_html.set_featureslist(abc_positions)
        if set_list != []:
            dic.update(pre_html.get_simplefeatures(dic_html))

        pre_extern = Pre_processing_EXTERN()
        set_list = pre_extern.set_featureslist(abc_positions)
        if set_list != []:
            dic.update(pre_extern.get_simplefeatures(dic_html))
        
        instance = []
        for i in range(len(abc_positions)):
                instance.append(dic[abc_positions[i]][0])    
        return self.model.predict([instance])[0]

#EXEMPLO PARA GERAR DATAFRAME COM FEATURES
'''
control = Controller()
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

df = control.get_features_fromlist(URL_LIST, page_list)
df.to_csv('DF_EXAMPLE.csv', index = False)
'''

#EXEMPLO DE CLASSIFICAÇÃO UTILIZANDO ALGUM MODELO EM FEATURES
'''
page = {'url' : 'https://google.com.br', 'ip': '124.0.0.1'}
file = open('google.html', 'r')
html = file.read()
file.close()
page['html'] = html
control = Controller()
print("Predict: ", control.predict(page), "\nPhishing = 1 and Not Phishing = 0")
'''

