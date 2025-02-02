<?php
session_start(); // Rozpoczęcie sesji, wymagane dla obsługi CSRF

// Generowanie tokenu CSRF przy żądaniu GET
if ($_SERVER["REQUEST_METHOD"] === "GET") {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Walidacja tokenu CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Nieprawidłowy token CSRF!");
    }

    // Pobieranie danych z formularza
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm-password'];

    // Połączenie z bazą danych
    $servername = "localhost";  // Domyślnie localhost dla XAMPP
    $dbname = "szermierka_db";  // Nazwa bazy danych
    $dbuser = "root";           // Domyślnie root dla XAMPP
    $dbpassword = "";           // Puste hasło domyślnie

    $conn = new mysqli($servername, $dbuser, $dbpassword, $dbname);
    if ($conn->connect_error) {
        die("Błąd połączenia: " . $conn->connect_error);
    }

    // Walidacja danych
    $error_message = "";

    // 1. Sprawdzenie, czy nazwa użytkownika lub email jest zajęta
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $error_message = "Nazwa użytkownika lub adres e-mail jest już zajęty!";
    }
    $stmt->close();

    // 2. Sprawdzenie poprawności adresu e-mail
    if (!$error_message && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = "Podano nieprawidłowy adres e-mail!";
    }

    // 3. Sprawdzenie siły hasła
    if (!$error_message && (
        strlen($password) < 9 ||
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[0-9]/', $password) ||
        !preg_match('/[\W]/', $password)
    )) {
        $error_message = "Hasło musi zawierać co najmniej 9 znaków, 1 dużą literę, cyfrę i znak specjalny!";
    }

    // 4. Sprawdzenie, czy hasła się zgadzają
    if (!$error_message && $password !== $confirm_password) {
        $error_message = "Hasła nie zgadzają się!";
    }

    // Błedow brak to zapisujemy usera do bazy
    if (!$error_message) {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashed_password);
        if ($stmt->execute()) {
            // Wyczyszczenie tokenu CSRF po użyciu (opcjonalne, dla bezpieczeństwa)
            unset($_SESSION['csrf_token']);
            header("Location: login.php");
            exit;
        } else {
            $error_message = "Wystąpił błąd podczas zapisywania danych!";
        }
        $stmt->close();
    }
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rejestracja - Szermierka Historyczna</title>
    <link rel="stylesheet" href="../Style/Style_sub/style_register.css">
</head>
<body class="body">


<nav class="Navigation">
    <div class="Top_menu">
        <h1 class="title">SZERMIERKA HISTORYCZNA</h1>
        <p class="subtitle">Rejestracja do serwisu</p>
    </div>
</nav>

<!-- formularz rejestracji -->
<div class="register-container">
    <h2>Załóż konto</h2>
    <form class="register-form" action="register.php" method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

        <label for="username">Nazwa użytkownika</label>
        <input type="text" id="username" name="username" required>

        <label for="email">Adres email</label>
        <input type="email" id="email" name="email" required>

        <label for="password">Hasło</label>
        <input type="password" id="password" name="password" required>

        <label for="confirm-password">Potwierdź hasło</label>
        <input type="password" id="confirm-password" name="confirm-password" required>

        <button type="submit">Zarejestruj się</button>
    </form>

    <!-- błąd komunikat-->
    <?php if (isset($error_message) && $error_message): ?>
        <div class="error-message">
            <p><?php echo htmlspecialchars($error_message); ?></p>
        </div>
    <?php endif; ?>

    <div class="register-footer">
        <p>Masz już konto? <a href="login.php">Zaloguj się</a></p>
    </div>
</div>

<footer class="footer">
    <p>&copy; 2024 Twoja Firma. Wszystkie prawa zastrzeżone.</p>
    <p><a href="privacy-policy.html">Polityka prywatności</a> | <a href="terms-of-service.html">Warunki użytkowania</a></p>
</footer>

</body>
</html>
