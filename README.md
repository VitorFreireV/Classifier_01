# Classifier_01
Em processo

Python 3.8, libs em requirements.txt. 


Função classifier recebe um dicionario no fomarto {'url': 'xxx', 'html' : """HTML""", 'ip': 'x.x.x.x', 'redirect' : 0}.

Redirect é número de redirecionamentos(tenho que melhorar a função de acordo com a organização dos dados), para omitir passe 'redirect' : -1.

Retorna 1 caso classifique como phishing e 0 como spam.

Exemplo de dicionario de entrada:

{'url': 'http://sing.pish.ounao.goggle.com/', 'html': """ <!DOCTYPE html>\n<html>\n<body>\n<\h\1>My First Heading</h1>\n<p>My first paragraph.</p>\n</body>\n</html>""", 'ip' : '0.11.0.1', 'redirect': 0}
