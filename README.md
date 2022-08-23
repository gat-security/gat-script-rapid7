# GAT Integration Rapid7
<img align="right" height="70" src="https://www.gat.digital/wp-content/uploads/2021/05/logo-gat-padrao-negativo.png">

Conversor de reports ```.xml``` do Rapid7 para arquivos ```.csv``` aceitos pelo Custom Parser do GAT Core.

## Pré Requisitos

* Python 3.x
* Conta ativa no GAT
* Chave de API do GAT (https://documenter.getpostman.com/view/7858992/TzCMdoMv?version=latest)
* Biliotecas em ```requirements.txt```


## Configuração Inicial

1. Clone o repositório na sua máquina

2. Abra o ```cmd``` na pasta do repositório

3. Instale as bibliotecas do arquivo ```requirements.txt``` com o comando:
```cmd
pip install -r src/requirements.txt
```

4. Configure no arquivo ```src/config.json``` sua **URL GAT Core** e sua **Chave de API**

```json
  "url": "exemplo.gat.digital",
  "bearer": "d3f8666c-a6af-4a94-98b9-f15000000000",
```

5. Além disso, é necessário ter os templates do Custom Parser criados no GAT Core e seus nomes respectivamente configurados no arquivo ```src/config.json``` nos campos ```Template_Name```.

```json
  "templates":{
    "NexposeReportV1": "Template_Name",
    "NexposeReportV2": "Template_Name",
    "QualysGuard": "Template_Name"
  }
```


## Features

Conversão para o formato aceito pelo GAT Core e import automático no GAT Core utilizando a API do Custom Parser dos seguintes reports do Rapid7:
* NexposeReportV2
* NexposeReportv1
* QualysGuard

## Modo de Uso

1. Realize a configuração inicial descrita anteriormente
2. Insira os reports que deseja importar para o GAT Core na pasta ```xmls``` (certifique-se de que seus reports estão na lista de formatos aceitos)
3. Abra o ```cmd``` na pasta raiz do repositório baixada
4. Execute o script com o comando
```cmd
python src/main.py
```

## Resultado esperado

Caso tenha executado todas as etapas, o esperado é a criação dos arquivos ```.csv``` na pasta ```csvs``` referentes a cada report inserido. Além disso, é esperado que os apontamentos e ativos destes relatórios tenham sido importados para sua conta do GAT Core.
