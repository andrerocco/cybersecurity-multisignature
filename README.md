# Mission: Digital Signature

[Repositório do desafio](https://https://github.com/Araggar/sgc-challenge)

## Descrição do desafio

Parabéns por ter chegado até esta etapa do processo seletivo do Laboratório de Segurança em Computação. Se você está lendo este texto é porque optou, ou está pensando em optar, pelo desafio em C++. "A sua missão, caso decida aceitá-la", é propor e desenvolver um protocolo de assinaturas múltiplas. Imagine um cenário onde n operadores, precisam decidir sobre o desligamento de uma usina nuclear. Para tanto, faz-se necessário que todos os envolvidos (os n operadores) assinem um documento digital, categorizando um acordo entre as partes. Seu objetivo é implementar uma aplicação simples, para simular este cenário. Cada operador nesse problema conta com um par de chaves RSA de 2048 bits e um certificado digital que o identifica. Você deve cumprir os seguintes objetivos:

-   A aplicação deve ser feita utilizando como base o Dockerfile disponibilizado em https://github.com/Araggar/sgc-challenge;
-   A aplicação deve receber como entrada um documento do tipo PDF;
-   Todos os operadores devem poder assinar o documento. Você deve definir como armazenará estas assinaturas;
-   Caso todos os operadores assinem o documento, o sistema deve fomecer o conjunto das assinaturas. Caso contrário é preciso informar que não foi possível entrar em um acordo;
-   Caso o acordo seja firmado, deve ser possível verificar as assinaturas geradas;

Para este desafio você deve utilizar, obrigatoriamente a linguagem de programação C++ e o wrapper OpenSSL desenvolvido pelo LabSEC, a [libcryptosec](https://github.com/LabSEC/libcryptosec). Qualquer dúvida poderá ser esclarecida via e-mail, ou pessoalmente, mediante um acordo de horários. Além da aplicação, pedimos que o candidato entregue um relatório de até 3 páginas contendo os seguintes tópicos:

-   Uma explicação de como as múltiplas assinaturas são armazenadas e verificadas;
-   Uma explicação de como as sua aplicação funcionaria na prática, por exemplo, em que ordem e como os operadores se apresentariam. Tente englobar os conceitos de certificação digital e assinatura digital;
-   Uma explicação de como se executa a sua aplicação;

### Links úteis:

1. https://araggar.github.io/sgc-challenge/
2. https://github.com/Araggar/sgc-challenge/
3. https://github.com/LabSEC/libcryptosec
4. https://www.openssl.org/source/old/1.0.2/

## Como executar

### Pré-requisitos

-   Possuir o [Docker](https://www.docker.com/) instalado e configurado na máquina.

### Executando o desafio

Com o serviço do Docker inicializado, acesse a pasta `docker/` deste repositório com `cd docker/` e execute os passos abaixo.

1. Caso seja a primeira vez que você está executando, execute os seguintes comandos:

```bash
# Construa a imagem do docker
docker build -t sgc .

docker run --name sgc -ti sgc
# ou (caso queria que o diretório local seja sincronizado com o diretório do container)
docker run -ti --name sgc -v ./:/home/labsec/challenge sgc bash
```

2. Caso já tenha executado alguma vez, execute os seguintes comandos:

```bash
# Inicie o container
docker start sgc

docker exec -ti sgc /bin/bash
```

Para acessar o diretório contendo o código fonte do desafio, compilar e executar o programa, siga os passos abaixo.

Acesse o diretório do desafio:

```bash
cd /home/labsec/challenge/
```

Compile o programa:

```bash
make all
```

Execute o programa:

```bash
./challenge.out testfile.pdf
```
