from preprocess.URLModel import Pre_processing_URL
from preprocess.HTMLModel import Pre_processing_HTML
from sklearn.ensemble import RandomForestClassifier
from model.clf_positions import clf_positions
import joblib

class Classifier():
    def __init__(self):
        self.model = joblib.load('model/clf')    

    def predict(self, dic_html):
        pre_url = Pre_processing_URL()
        dic = pre_url.get_simplefeatures(dic_html)
        pre_html = Pre_processing_HTML()
        dic.update(pre_html.get_simplefeatures(dic_html))
        
        
        instance = []
        for i in range(len(clf_positions)):
            if clf_positions[i] == 'NumberRedirect':
                 instance.append(dic_html['redirect'])
            else:    
                instance.append(dic[clf_positions[i]])    
        return self.model.predict([instance])[0]


'''
dic = {'url': 'http://sing.pish.ounao.goggle.com/', 'html': """ <!DOCTYPE html>\n<html>\n<body>\n<h1>My First Heading</h1>\n<p>My first paragraph.</p>\n</body>\n</html>""", 'ip' : '0.11.0.1', 'redirect' : 0}

classificador = Classifier()
print(classificador.predict(dic))
'''
