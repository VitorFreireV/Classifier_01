from preprocess.URLModel import Pre_processing_URL
from preprocess.HTMLModel import Pre_processing_HTML
from sklearn.ensemble import RandomForestClassifier
from model.abc_positions import abc_positions
import joblib

class Classifier():
    def __init__(self):
        self.model = joblib.load('model/abc')    

    def predict(self, dic_html):
        pre_url = Pre_processing_URL()
        dic = pre_url.get_simplefeatures(dic_html)
        pre_html = Pre_processing_HTML()
        dic.update(pre_html.get_simplefeatures(dic_html))
        
        
        instance = []
        for i in range(len(abc_positions)):
                instance.append(dic[abc_positions[i]])    
        return self.model.predict([instance])[0]
