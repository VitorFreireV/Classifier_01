from sklearn.model_selection import cross_val_predict
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score,confusion_matrix
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
import pandas as pd
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import KFold, StratifiedKFold
from operator import itemgetter
from sklearn.preprocessing import StandardScaler

class Avaliator:
    def __init__(self, DataFrame):
        self.model = {'RFC':RandomForestClassifier(max_depth = 10, random_state = 2, n_estimators = 800, min_samples_split = 2, min_samples_leaf = 1, bootstrap = False, max_features = 'auto'),
                      'LR':LogisticRegression(random_state=2, max_iter = 500), 
                      'GaussianNB':GaussianNB(),  
                      'SVM':make_pipeline(StandardScaler(), SVC(C=1.0, kernel='rbf', degree=3, gamma='auto')), 
                      'AdaBoost':AdaBoostClassifier(base_estimator = DecisionTreeClassifier(max_depth=3), random_state = 2, n_estimators = 400, learning_rate = 0.8),
                      'Tree': DecisionTreeClassifier(max_depth = 10)
                      }
        self.df = DataFrame
        self.X = DataFrame.drop(['class', 'id'], axis = 1).values
        self.Y = DataFrame['class'].values

    def feature_importance_rfc(self):
        rfc = RandomForestClassifier(max_depth = 5, random_state = 0, n_estimators = 100)
        rfc.fit(self.X, self.Y)
        importance = rfc.feature_importances_
        labels =  (self.df).drop(['class', 'id'], axis = 1).keys()
        dic_importance = {}
        for i in range(0, len(importance)):
            dic_importance[labels[i]] = importance[i]
        return dict(sorted(dic_importance.items(), key=itemgetter(1), reverse=True))

    def print_metrics(self, metrics):
        for key in metrics.keys():
            print(key + ': ', metrics[key])

    def get_allmetrics_crossval(self, model, cv = 10):
        cv = StratifiedKFold(n_splits = 10, random_state=2)  
        predict = cross_val_predict(model, self.X, self.Y, cv=cv)
        tn, fp, fn, tp = confusion_matrix(self.Y, predict, labels = [0,1]).ravel()
        metrics = {'Accuracy': accuracy_score(self.Y, predict), 'Precision': precision_score(self.Y, predict),
                'Recall': recall_score(self.Y, predict), 'F1 Score': f1_score(self.Y, predict), 'TRP':tp/len(self.Y[self.Y == 1]),
                'FPR':fp/len(self.Y[self.Y == 0]), 'FNR':fn/len(self.Y[self.Y == 1]), 'TNR':tn/len(self.Y[ self.Y == 0])}
        self.print_metrics(metrics)
        return metrics, predict

    def get_all(self, cv = 10):
        dic = {}
        for model in self.model.keys():
            dic[model] = {}
            print('***************\nModel: ', model)
            dic[model]['metrics'], dic[model]['predict'] = self.get_allmetrics_crossval(self.model[model], cv)
        return dic
