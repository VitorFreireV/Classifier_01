# EXTRAÇÃO DE RECURSOS E CLASSIFICAÇÃO DE PÁGINAS EM FALSAS E LÉGITIMAS.
Em processo

Python 3.8, libs em requirements.txt.

# ORGANIZAÇÃO DO CÓDIGO
Em preprocess estão os módulos de pré processamento assim como a base de conhecimento utilizada. Os modulos de pré processamento são dividos em URLModel, HTMLModel e EXTERNModel. Divisão feita de acordo com características dos atributos, em URLModel são atributos gerados a partir de url, em HTMLModel são atributos gerados a partir do código fonte da pagina e o EXTERNModel são atributos gerados a partir de fontes externas/redes como check Alexa, tempo de domínio, tempo de SLL e etc. Recurso de URL são os mais rápidos de serem gerados, seguidos de recursos provindo de HTML e por último de fontes externas. Cada módulo de extração funciona da mesma forma.

## Função modulo.set_features(lista_de_atributos)
Recebe uma lista de strings com os nomes dos atributos e seta para gerar somente esses atributos. Todos os nomes estão disponíveis nas listas preprocess/features_config.py.

## Função modulo.get_simplefeatures(dic_page)
Recebe um dicionário com informações da página {'url':<url>, 'ip':<ip>, 'html':<html>}, retorna um dicionário com nome de feature como chave e valor sendo o resultado da feature {'feature1': [result1], 'feature2':[result2], ...}.
 
## Função modulo.get_dffromlist(list_pages)
Recebe uma lista onde cada posição corresponde a um dicionário com os mesmos campos do dicionário da função get_simplefeatures e adiciona mais dois campos como id e class. Retorna um pd.DataFrame que pode ser usado diretamente pelo módulo Avaliator para avaliação de modelos de AM.

# Módulo Controller
Responsável por gerenciar todos os módulos, facilitando a implementação de novos módulos e paralelização do código. Atualmente possui duas funções, predict e get_dffromlist.
## Controller.predict(dic_page)
Recebe um dicionário com informações da página {'url':<url>, 'ip':<ip>, 'html':<html>}, carrega modelo configurado disponível em model/, classifica a página retornando 1 para páginas falsas e 0 para páginas legítimas.
 
## Controller.get_features_fromlist(features_list, page_list)  
Recebe a lista de variáveis a serem utilizadas, uma lista com informações de páginas e retorna um pd.dataframe pronto para ser usado por Avaliator.
