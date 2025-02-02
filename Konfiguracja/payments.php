<?php
session_start();
include('config.php');

// czy użytkownik jest zalogowany
if (!isset($_SESSION['user_id'])) {
    echo "Musisz być zalogowany, aby zobaczyć swoje opłaty.";
    exit;
}

$user_id = $_SESSION['user_id'];

// Zapytanie do bazy danych, aby pobrać opłaty użytkownika
$query = "SELECT * FROM Payments WHERE user_id = :user_id";
$stmt = $conn->prepare($query);
$stmt->bindParam(':user_id', $user_id);
$stmt->execute();

// Wyświetlanie
if ($stmt->rowCount() > 0) {
    echo "<h2>Twoje opłaty:</h2>";
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Kwota: " . $row['amount'] . " | Data: " . $row['payment_date'] . " | Status: " . $row['status'] . "<br>";
    }
} else {
    echo "Nie masz żadnych opłat.";
}
?>
