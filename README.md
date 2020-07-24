# Classifier_01
Em processo

Python 3.8, libs em requirements.txt. 


Função classifier recebe um dicionario no fomarto {'url': 'xxx', 'html' : """HTML""", 'ip': 'x.x.x.x'}.



Retorna 1 caso classifique como phishing e 0 como spam.

Exemplo:

from classifier import Classifier


page = {'url': 'xxx', 'html' : """HTML""", 'ip': 'x.x.x.x'}

model = Classifier()

response = model.predict(page)
