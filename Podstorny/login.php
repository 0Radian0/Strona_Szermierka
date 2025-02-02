<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Pobieranie danych z formularza logowania
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Połączenie z bazą danych
    $servername = "localhost";
    $dbname = "szermierka_db";
    $dbuser = "root";
    $dbpassword = "";

    $conn = new mysqli($servername, $dbuser, $dbpassword, $dbname);
    if ($conn->connect_error) {
        die("Błąd połączenia z bazą danych: " . $conn->connect_error);
    }

    // Sprawdzanie użytkownika w bazie danych łączymy tabelę users z payments
    $stmt = $conn->prepare("
        SELECT u.id, u.username, u.email, u.password, p.payment_status, p.due_date
        FROM users u
        LEFT JOIN payments p ON u.id = p.user_id
        WHERE u.username = ?
    ");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $db_username, $email, $hashed_password, $payment_status, $due_date);
        $stmt->fetch();

        // Weryfikacja hasła
        if (password_verify($password, $hashed_password)) {
            echo "Hasło poprawne!";

            // Dane poprawne, ustawienie sesji
            $_SESSION['username'] = $db_username;
            $_SESSION['email'] = $email;

            // Sprawdzanie statusu płatności
            if ($payment_status == 'paid') {
                $subscription_status = "Opłata została dokonana do " . $due_date;
            } else {
                $subscription_status = "Opłata zaległa. Proszę dokonać płatności.";
            }

            $_SESSION['subscription_status'] = $subscription_status;

            // Przekierowanie na stronę główną
            header("Location: ../index.php");
            exit();
        } else {
            echo "Błędne hasło!";
        }

    } else {
        $error_message = "Nie znaleziono użytkownika o podanej nazwie!";
    }

    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logowanie - Szermierka Historyczna</title>
    <link rel="stylesheet" href="../Style/Style_sub/style_login.css">
</head>
<body>

<nav class="Navigation">
    <div class="Top_menu">
        <h1 class="title">SZERMIERKA HISTORYCZNA</h1>
        <p class="subtitle">Logowanie do serwisu</p>
    </div>
</nav>

<div class="login-container">
    <h2>Zaloguj się</h2>
    <!-- Formularz logowania -->
    <form class="login-form" action="login.php" method="POST">
        <label for="username">Nazwa użytkownika</label>
        <input type="text" id="username" name="username" required>

        <label for="password">Hasło</label>
        <input type="password" id="password" name="password" required>

        <button type="submit">Zaloguj się</button>
    </form>

    <!-- bład logowania -->
    <?php if (isset($error_message)): ?>
        <div class="error-message">
            <p><?php echo htmlspecialchars($error_message); ?></p>
        </div>
    <?php endif; ?>

    <div class="login-footer">
        <p>Nie masz konta? <a href="register.php">Zarejestruj się</a></p>
    </div>
</div>

<footer class="footer">
    <p>&copy; 2024 Twoja Firma. Wszystkie prawa zastrzeżone.</p>
    <p><a href="privacy-policy.html">Polityka prywatności</a> | <a href="terms-of-service.html">Warunki użytkowania</a></p>
</footer>

</body>
</html>
