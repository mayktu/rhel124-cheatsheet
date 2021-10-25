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

------------------------------------------ 
## EXTRAS

- <br>
```
sudo ln -s /usr/bin/vim /usr/bin/vi
```

- <br>
```
echo alias rm='rm -i' >> /.bashrc
```

- <br>
```
umask 026   
```
-------------------------------------------
## Semana 2
- Mostra o diretorio corrente <br>
```
pwd
```

- Cria um arquivo com o nome de file1 <br>
```
touch file1
```

- Mostrar em formato longo e mostrar arquivos ocultos  <br>
```
ls -la
```

- Mostrar arquivos das pastas e subpastas recursivamente <br>
```
ls -R
```

- <br>
```
cd /home/user/Documents
```

- Volta para diretorio para o anterior <br>
```
cd -
```

- Sobe um ou dois diretorios na arvore <br>
```
cd ..
cd ../..
```

- Cria uma pasta chamada diretorio <br>
```
mkdir diretorio
```

- <br>
```
cp file1
```

- Copiar diretorio e seus arquivos dentro <br>
```
cp -r diretorio novodiretorio
```

- Mover ou renomear um arquivo <br>
```
mv file novofile
```

- Remover um arquivo <br>
```
rm file
```

- Remover os arquivos dentro de um diretorio <br>
```
rm -r diretorio
```

- Remover diretorio vazio <br>
```
rmdir diretorio
```

- <br>
```
mkdir pasta1 pasta2
```

- Cria se nao existir a pasta ja <br>
```
mkdir -p Thesis/pasta1 Thesis/pasta2
```

- <br>
```
cp -r Origem Destino
```

- Hard link nao funciona em diretorios
- Hard link do arquivo (MESMO SE O ORIGINAL FOR DELETADO, A REFERENCIA PERMANECE ACESSIVEL) <br>
```
ln newfile.txt /tmp/newfile-hlink2.txt
```

- Soft Link  <br>
```
ln -s origem destino
```

- <br>
```
*s* palavras que tenham 's' em qualquer lugar
? qualquer caractere
[as]* palavras que começam com a ou s
*[as] palavras que terminam em a ou s
*[as]* 
```

- cria 999999 pastas, com nome pasta1 pasta2 e por ai vai <br>
```
mkdir pasta{1..999999} 
```

- <br>
```
echo file{a{1,2},b,c}.txt
```

- <br>
```
armazenar valor em memoria
VARIABLENAME=value
ex:
USERNAME=operator

using:
echo ${USERNAME}
```

- uso de " e ' <br>
```
echo "My son is $son"
My son is Mayk
echo 'My son is $son'
My son is $son
```

- procurar palavras que tem passwd no nome no man <br>
```
man -k passwd
```

- Manual GUI completo <br>
```
pinfo passwd
```

- Guarda um carimbo do tempo em um arquivo <br>
```
date > /tmp/saved-timestamp
```

- Guarda as ultimas 100 linhas de um arquivo log em outro arquivo <br>
```
tail -n 100 /var/log/dmeesg > /tmp/last-100-boot-messages
```
- Concatena 4 arquivos em um <br>
```
cat file1 file2 file3 file4 > /tmp/all-four-in-one
```

- Joga a saida do ls para o outputfile <br>
```
ls -lai > outputfile 
```
--------------
PIPE

- A Saída vai para o arquivo file1(Recriando - caso ja exista ele sobreescreve) e o erro caso ocorra vai para o terminal<br>
```
comando > file1
```
- A Saída vai para o arquivo file1(Append - Adicionando no final do arquivo) e o erro caso ocorra vai para o terminal<br>
```
comando >> file1
```
- A saída vai para o terminal e o erro vai para o file1(Recriando - caso ja exista ele sobreescreve)<br>
```
comando 2> file1
```
- A saída vai para o terminal e o erro vai para o lixo(null)<br>
```
comando 2> /dev/null
```

- A saida e o erro vai para o mesmo arquivo file1(Recriando - caso ja exista ele sobreescreve)<br>
```
comando > file1 2>&1 
comando &> file1
```
- A saida e o erro vai para o mesmo arquivo file1(Append - Adicionando no final do arquivo)<br>
```
comando >> file1 2>&1
comando &>> file1
```
- A saida e os erros vai para o terminal e para o arquivo file1 ao mesmo tempo<br>
```
comando | tee file1
```

-------------------------------------------
- Listar as variaveis do ambiente<br>
```
env
```
- Setando Variaveis automaticamente<br>
```
~/.bashrc
```

- Retirando variaveis<br>
```
unset nomedavariavel
```
- Retirar variavel sem desconfigurar<br>
```
export -n nomedavariavel
```

- Informacoes do user atual<br>
```
id
```
- Informacoes do user02<br>
```
id user02
```
- Mostra o dono (-l) do arquivo ou diretorio<br>
```
ls -ld dir1
ls -l file1
```
- Lista todos os processos atuais mostrando os responsaveis por cada processo<br>
```
ps -au
```
- Troca de usuario ou para superusuario<br>
```
su 
su -
su - user02
```
- Bloqueia e Desbloqueio a senha do user02 colocando um ! no password<br>
```
sudo usermod -L user02
sudo usermod -U user02
```
- logs são salvos em /var/log/secure<br>

-<br>
```
sudo -i
```
- Configurando o acesso ao comando sudo<br>
```
/etc/sudoers.d/nomedousuario

user01 ALL=(ALL) ALL
%group01 ALL=(ALL) ALL
user03 ALL=(ALL) NOPASSWD:ALL
```
- O comando su - seta root exatamento como um login normal ignorando configurações de ambiente feitas pelo sudo.<br>



- Apaga o usuario, o segundo apaga o usuario e sua home<br>
```
userdel nomeusuario
userdel -r nomeusuario
```
- Encontrar todos os arquivos e diretorios nao proprietarios<br>
```
find / -nouser -o -nongroup
```
- (-g) GID<br>
```
sudo groupadd -g 10001 group01
```

- Cria um grupo do sistema (-r)<br>
```
sudo groupadd -r group02
```
- (-n) newname<br>
```
sudo groupmod -n group0022 group02
```

- (-g) novo GID<br>
```
sudo groupmod -g 20000 group0022
sudo groupdel group0022
```
- Altera grupo principal<br>
```
sudo usermod -g alunos user02
```
- Acrescenta grupo complementar<br>
```
sudo usermod -aG mestrado user02
```


- <br>
```
sudo chage -m 0 -M 90 -W 7 -I 14 user03
```
- Arquivo que contem as informacoes de expiracao de senha<br>
```
/etc/login.defs
```
- Programar trancamento de conta/ Desabilitar interacao com o shell<br>
```
sudo usermod -L -e 2019-10-05 user03
usermod -s /sbin/nologin user03
// VC PODE CALCULAR DATA COM date -d "+180 days" +%F
```


- define recursivamente permissoes para a arvore (-R)<br>
## g group, o others, a all,+,-,=
chmod -R g+rwX demodir
chmod go-rw file1
chmod a+x file2
chmod 750 mayk.pdf

#chown (change owner) recursivo de toda a arvore
chown -R student teste_file

# mudando o dono do arquivo
chown student teste_file

# Muda o grupo dono do arquivo para admins
chown :admins teste_dir

# Aqui vc muda o user dono e group dono ao msm tempo (owner:group)
chown visitante:aluno perfilmayk

# executa como se fosse o user fosse dono do arquivo
chmod u+s teste

# executa como se o group fosse o dono do arquivo
chmod g+s teste

# usuarios com acesso a essa pasta so podem remover e editar os arquivos criados por eles
chmod o+t pastateste

# Umask
umask u-x,g=r,o+w


--------------------------------------------------SEMANA 4

# Running (R), Stopped(T), Sleeping(S,D,K,I), Zombie(Z,X)

#
ps
top
w
ps aux
ps lax
ps -ef

#
sleep 10000 &
jobs
fg %l
bg %l

#
kill -l
ps aux | grep job
kill 5194
kill -9 5194
kill -SIGTERM 5194
killall control

# 
ps aux | grep job
killall control

# Mata os processos de acordo com algum criterio
pkill control
pkill -U user 

# Caca os processos que tem bob como user pai
pgrep -l -u bob
w -h -u bob

# Mata os processos de tty3
pkill -t tty3
pkill -SIGKILL -t tty3


#matar somente os filhos do processo
pstree -p bob
pkill -P 8391
pgrep -l -u bob
pkill -SIGKILL -P 8391
pkill -l -u bob

#tempo ativo
uptime

# informacoes CPU
lscpu

#
systemctl is-active sshd.service
systemctl is-enabled sshd.service
systemctl is-failed sshd.service
systemctl start NetworkManager
systemctl stop NetworkManager
systemctl restart NetworkManager
systemctl reload NetworkManager
systemctl reload-or-restart NetworkManager



# Link dentro do /dev/null que evita sua inicializacao
systemctl list-dependencies NetworkManager
systemctl mask NetworkManager
systemctl unmask NetworkManager

#habilitar um serviço para iniciar com boot
systemctl enable NetworkManager
systemctl disable NetworkManager

#
ssh-keygen
ssh-keygen -f .ssh/key-with-pass

# Copia a chave para o remotehost destino
ssh-copy-id -i .ssh/key-with-pass.pub user@remotehost
ssh -i .ssh/key-with-pass user@remotehost

# Adicionar a chave na memoria para nao ficar pedindo senha em varios momentos
eval $(ssh-agent)
ssh-add
ssh-add .ssh/key-with-pass
ssh user@remotehost
ssh -i .ssh/key-with-pass user@remotehost


#Bloquear acesso de super usando ssh
PasswordAuthentication no
PermitRootLogin no
/etc/ssh/sshd_configroot
systemctl reload sshd




#
prog1 args; prog2 args; ..
prog1 & prog2 
prog1 && prog2


#
/etc/systemd/system/multi-user.target.wants/ntp.service -> /usr/lib/systemd/system/ntpd.service

#
systemctl isolate rescue.target
systemctl isolate emergency.target

#
ssh -L [nome_ou_end_local:]porta_local:host_destino:porta_destino host_intermediário [comando]


------------------------------------------------------------------------SEMANA 5


# Logs relacionados a jobs agendados
/var/log/cron

# Log relacionado inicialização de sistema
/var/log/boot.log

# Grava as mensagens da instalação com qualquer prioridade em /var/log/secure
authpriv.* /var/log/secure

# Armazenando log de nivel alert em secure
authpriv.alert /var/log/secure
sudo systemctl restart rsyslog

#pingando um log teste
logger -p authpriv.alert "Logging test authpriv.alert"
sudo tail /var/log/auth-errors

# Log rotation, tempo de duração do log
/etc/logrotation.conf

# Enviar mensagens para o serviço rsyslog
logger -p local17.notice "Log entry created on host"

# Captura todas as mensagens de qlq prioridade e debug ou priodade acima e salva no messages-debug
vim /etc/rsyslog.d/debug.conf
*.debug /var/log/messages-debug

#
/run/log/journal

# Jornal de eventos
journalctl

# Eventos em tempo real 
journalctl -f

# Eventos de acordo com o tempo
journalctl --since "-1 hour"
journalctl -o verbose
journalctl -p warning
journalctl _UID=81
journalctl _SYSTEMD_UNIT=sshd.service _PID=1182

#Se /var/log/journal nao existir systemd-journald nao esta preservando os journals
/etc/systemd/journald.conf
Storage=persistent
sudo systemctl restart systemd-journald.service

# Selecionar zona apropriada
tzselect

# Seta o timezone para America
timedatectl set-timezone America/Phoenix
timedatectl set-time 9:00:00

#Sincronização automatica do tempo
timedatectl set-ntp true


#
/etc/chrony.conf
systemctl restart chronyd
chronyc sources -v

# Lista todas as interfaces de rede disponveis no sistema
ip link show

# IP ATUAL DO ENS3
ip addr show ens3

#Estatisticas a respeito de uma interface da rede
ip -s link show ens3

# teste de conexão
ping -c3 192.0.2.254
ping6 2001:db8:0:1::1

# Mostrar A tabela de rota
ip route
ip -6 route

# Traçando a rota ocupada pelo trafego
tracepath acess.redhat.com
tracepath6 acess.redhat.com

#
/etc/services

# Mostrar estatisticas das portas sockets
ss -ta

# Mostrar o ip atual de todas as interfaces
ip addr


#
/etc/sysconfig/network-scripts

# Mostra o status de todos os dispositivos
nmcli dev status

# Mostrar lista das conexoes
nmcli con show

# Mostrar lista das conexoes ativas
nmcli con show --active

# Adiciona uma nova conexao de rede
nmcli con add con-name eno2 type ethernet ifname eno2
nmcli con add con-name eno2 type ethernet ifname eno2 ipv4.adress 192.168.0.5/24 ipv4.gateway 192.168.0.254
nmcli con add con-name eno2 type ethernet ifname eno2 ipv6.adress 2001:db8:0:1::c000:207/64 ipv6.gateway 2001:db8:0:1::1 ipv4.adress 192.0.2.7/24 ipv4.gateway 192.0.2.1

# Conecta e disconecta de alguma conexao de rede
nmcli con up static-ens3
nmcli dev dis ens3

# Modificando alguma configuracao de alguma rede
nmcli con show static-ens3
nmcli con mod static-ens3 ipv4.adress 192.0.2.2/24 ipv4.gateway 192.0.2.254

# Recarrega a rede
nmcli con reload

# Deletando uma rede
nmcli con del nomedarede

#editando manualmente uma rede
/etc/sysconfig/network-scripts/ifcfg-Wired_connection
nmcli dev dis Wired Conecction
nmcli con reload
nmcli con up Wired Conection

# Consulta o hostname
/etc/hostname

# Consulta o hostname
hostname

# Setar um nome o hostname
hostnamectl set-hostname host@example.com

#Consulta a situação do hostname
hostnamectl status

# Consulta os hosts atuais
cat /etc/hosts

# Controla como a query vai ser performada na rede, se sera usada como busca, dominio,etc
/etc/resolv.conf

# Testar resolução de Nome de DNS
getent hosts class (class é o apelido colocado em /etc/hosts
host classroom.example.com

# Habilitar para iniciar automatico uma rede
nmcli con mod "Wired connection 1" connection.autoconnect yes


-------------------------------------------------  SEMANA 6

# c create, x extract, t lista, v verbose, f file, p preservar permissoes
tar -cf abc.tar file1 file2 file3
tar -cf /root/etc.tar /etc
tar -xf /root/etc.tar /etc
tar -tf /root/etc.tar /etc

# Zipar e deszipar
```
gzip abc.tar
bzip2 abc.tar
xz abc.tar
gunzip abc.tar.gz
bunzip2 abc.tar.bz2
unxz abc.tar.xz
```

# Utilizando os dois de uma vez
```
tar -czf abc.tar file1 file2 file3
tar -cjf /root/etc.tar /etc
tar -xJf /root/etc.tar /etc
```

# Copia segura de arquivos (origem/destino) - da pra usar varios
```
scp /etc/yum.conf /etc/hosts remoteuser@remotehost:/home/remoteuser
scp remoteuser@remotehost:/etc/hostname /home/user
```

# Copiar toda a arvore
```
scp -r root@remoteuser:/var/log /tmp
```

# Sessao interativa para baixar e enviar arquivos remotamente
```
sftp remoteuser@remotehost
mkdir hostbackup
cd hostbackup
//Envia o arquivo do host para o remote
put /etc/hosts
//Puxa um arquivo do Remote para o host
get /etc/hosts
exit
```

# Sincronizando arquivos e diretorios (a archive mode, v verbose)
```
rsync -av /var/log /tmp
rsync -av /var/log remotehost:/tmp
rsync -av remotehost:/var/log /tmp
```

#
```
subscription-manager register --username=yourname --password=yourpassword
subscription-manager list --available | less
subscription-manager attach --auto
subscription-manager attach --pool=poolID
subscription-manager list --consumed
subscription-manager unregister
```

# Instalar modulos (pacotes rpm)
```
yum module install perl
```

----------------------------------------------------- SEMANA 7


# Mostra o espaco livre disponivel nos discos(-h pra humano ler)
```
df
df -h
```

# Uso de disco da pasta (-h para leitura humana)
```
du /usr/share/
du -h /usr/share/
```

# Detalhes dos blocos de todos os dispositivos
```
lsblk
```

# Montagem do bloco poor nome
```
mount /dev/vdb1 /mnt/data
```

# Detalhes do bloco com detalhes do UUID, tipo de montagem
```
lsblk -fp
```

# montagem por UUID
```
mount UUID="124s8afasgas9-12121gafeq14-215125adawd" /mnt/data
```

# desmontar uma arvore de bloco
```
umount /mnt/data
```

# Mostra todos os arquivos que estao abertos e em processos do diretorio desejado
```
lsof /mnt/data
```


# Atualiza o banco de dados de busca
```
updatedb
```

# Utiliza o banco para fazer uma busca
```
locate passwd
locate image
```

# Case sensitive
```
locate -i messages
locate -n 5 snow.png
```

# Busca em tempo real 
```
find / -name sshd_config
find / -name '*.txt'
find /etc -name '*pass*'
find / -iname '*messages*'
```

# Busca baseada em dono
```
find -user user
find -group user
find -uid 1000
find -gid 1000
find / -user root -group mail
```

#Busca pela permissao
```
find /home -perm 764
find /home -perm /442
find -perm -002
```

# Busca por tamanho
```
find -size 10M
find -size +10G
find -size -10k
find / -mmin 120
find / -mmin +200
find / -mmin -150
```

#Busca baseada por tipo
```
find /etc -type d
find /etc -type f
find /etc -type l
find /etc -type b
find / -type f -links +1
```

------------------------------------------------------- CAPITULO 17


