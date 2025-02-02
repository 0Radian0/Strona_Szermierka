<?php
session_start();
session_unset();  // Usuwa wszystkie zmienne sesyjne
session_destroy();  // Zamyka sesję
header("Location: ../index.php");
exit;
?>
