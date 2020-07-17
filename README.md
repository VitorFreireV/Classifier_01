# Classifier_01
Em processo

Python 3.8, libs em requirements.txt. 


Função classifier recebe um dicionario no fomarto {'url': 'xxx', 'html' : """HTML""", 'ip': 'x.x.x.x', 'redirect' : 0}.

Redirect é número de redirecionamentos(tenho que melhorar a função de acordo com a organização dos dados), para omitir passe 'redirect' : -1.

Retorna 1 caso classifique como phishing e 0 como spam.

Exemplo

from classifier import Classifier

page = {'url': 'xxx', 'html' : """HTML""", 'ip': 'x.x.x.x', 'redirect' : 0}
model = Classifier()
reponse = model.predict(page)
