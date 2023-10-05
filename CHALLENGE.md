# Mission: Digital Signature

Olá candidato.

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

### Links

1. https://araggar.github.io/sgc-challenge/
2. https://github.com/Araggar/sgc-challenge/
3. https://github.com/LabSEC/libcryptosec
4. https://www.openssl.org/source/old/1.0.2/
