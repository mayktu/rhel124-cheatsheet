# Comando uteis RH124 - RHEL 8 - JUNHO 2020

## Semana 1
- Data completa <br>
```
date
```

- Mostra a hora com no formato 12PM <br>
```
date +%r
```

- Que tipo de arquivo zcat é? comando file diz <br>
```
file zcat
```

- Mostrar quantidade de linhas, palavras e bytes <br>
```
wc zcat
wc -l /etc/passwd ; wc -l /etc/group 
wc -c /etc/group /etc/hosts
```

- Mostrar as 10 primeiras linhas do arquivo <br>
```
head zcat
```

- Mostrar as 10 ultimas linhas do arquivo <br>
```
tail zcat
```

- Repetir o ultimo comando <br>
```
!!
```

- Mostrar as ultimas 20 linhas <br>
```
tail -n 20 zcat
```

- mostrar historico <br>
```
history
```

#Reutilizar segundo comando do historico <br>
```
!2
```

- Repete o ultimo comando ls <br>
```
!ls
```

- Configurando acesso ssh com a chave <br>
```
chmod 600 mylab.pem
ssh -i mylab.pem remoteuser@remotehost
```

- Mostra o user atual <br>
```
whoami
```

- Combinar duas saidas, antes mostrar a proxima entrada shell <br>
```
comando1; comando2
```

- Somente a hora atual <br>
```
date +%R
```

- Somente a data <br>
```
date +%x
```

- Mostrar oq tem no arquivo <br>
```
cat file1 file2
```

- Mostrar como pagina <br>
```
less file1
```

- PESQUISAR SOBRE O more <br>

- Volta o cursor pro comeco da linha <br>
```
Ctrl + A
```

- Volta o cursor pro final da linha <br>
```
Ctrl + E
```
