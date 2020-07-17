from preprocess.URLModel import Pre_processing_URL
from preprocess.HTMLModel import Pre_processing_HTML
from sklearn.ensemble import RandomForestClassifier
from model.clf_positions import clf_positions
import joblib

def classifier(dic_html):
    pre_url = Pre_processing_URL()
    dic = pre_url.get_simplefeatures(dic_html)
    pre_html = Pre_processing_HTML()
    dic.update(pre_html.get_simplefeatures(dic_html))
    
    loaded_model = joblib.load('model/clf')
    instance = []
    for i in range(len(clf_positions)):
        if clf_positions[i] == 'NumberRedirect':
             instance.append(dic_html['redirect'])
        else:    
            instance.append(dic[clf_positions[i]])    
    return loaded_model.predict([instance])[0]


