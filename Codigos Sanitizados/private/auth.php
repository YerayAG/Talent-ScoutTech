<?php
require_once dirname(__FILE__) . '/conf.php';

session_start();

$userId = FALSE;

function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) return FALSE;

    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_SESSION['userId'] = $userId;
        return TRUE;
    } else {
        return FALSE;
    }
}

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = $_POST['password'];

    if (areUserAndPasswordValid($username, $password)) {
        $_SESSION['user'] = $username;
        header("Location: index.php");
        exit();
    } else {
        $error = "Invalid user or password.";
    }
}

if (isset($_POST['Logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}

$login_ok = isset($_SESSION['user']);

if (!$login_ok) {
    $error = $error ?? "This page requires you to be logged in.";
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Authentication page</title>
</head>
<body>
<header class="auth">
    <h1>Authentication page</h1>
</header>
<section class="auth">
    <div class="message">
        <?= htmlspecialchars($error) ?>
    </div>
    <section>
        <div>
            <h2>Login</h2>
            <form action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" method="post">
                <label for="username">User</label>
                <input type="text" id="username" name="username" required><br>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required><br>
                <input type="submit" value="Login">
            </form>
        </div>

        <div>
            <h2>Logout</h2>
            <form action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>" method="post">
                <input type="submit" name="Logout" value="Logout">
            </form>
        </div>
    </section>
</section>
<footer>
    <h4>Puesta en producción segura</h4>
    &lt; Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a> &gt;
</footer>
</body>
</html>
<?php
    exit(0);
}
?>