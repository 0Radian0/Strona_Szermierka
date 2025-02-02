<?php
// Rozpocznij sesję
session_start();

// Sprawdzenie, czy użytkownik jest zalogowany
$is_logged_in = isset($_SESSION['username']) && isset($_SESSION['email']);
$user_email = $is_logged_in ? $_SESSION['email'] : null;
$subscription_status = '';

if ($is_logged_in) {
    // Połączenie z bazą danych
    $servername = "localhost";
    $dbname = "szermierka_db";
    $dbuser = "root";
    $dbpassword = "";

    $conn = new mysqli($servername, $dbuser, $dbpassword, $dbname);
    if ($conn->connect_error) {
        die("Błąd połączenia z bazą danych: " . $conn->connect_error);
    }

    // Pobranie id usera
    $username = $_SESSION['username'];

    // Zapytanie do bazy, historia platnoscii
    $stmt = $conn->prepare("SELECT p.amount, p.payment_date, p.payment_status, p.due_date FROM payments p JOIN users u ON p.user_id = u.id WHERE u.username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    $payment_history = $result->fetch_all(MYSQLI_ASSOC);

    if (empty($payment_history)) {
        $subscription_status = "Brak zapisanych płatności.";
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
        <title>Szermierka historyczna</title>
        <link rel="stylesheet" href="Style/Style_main/style.css">
        <link rel="stylesheet" href="Style/Style_sub/style_responsive_1024.css">
        <link rel="stylesheet" href="Style/Style_sub/style_responsive_884.css">
        <link rel="stylesheet" href="Style/Style_sub/style_responsive_480.css">
</head>
<body>

<nav class="Navigation">
     <div class="Top_menu">
            <h1 class="title">SZERMIERKA HISTORYCZNA</h1>
            <p class="subtitle">Klub przy Politechnice Lubelskiej</p>
            <ul class="desktop-menu">
                <li><a href="https://drogamiecza.pl/hema-walki-rycerskie/">HEMA</a></li>
                <li><a href="#">REKO</a></li>
                <li><a href="#kim_jestesmy">O nas</a></li>
                <li><a href="#map">Lokalizacja</a></li>
                <li><a href="#treningi">Treningi</a></li>
                <li><a href="#kontakt">Kontakt</a></li>
            </ul>
        </div>

    <!-- Drop menu  -->
    <div class="drop_menu">
        <button class="menu_icon"></button>
        <div class="content">
            <a href="https://drogamiecza.pl/hema-walki-rycerskie/">HEMA</a>
            <a href="">REKO</a>
            <a href="#kim_jestesmy">O nas</a>
            <a href="#map">Lokalizacja</a>
            <a href="#treningi">Treningi</a>
            <a href="#kontakt">Kontakt</a>
            <?php if ($is_logged_in): ?>
                <a href="Konfiguracja/logout.php">Wyloguj się</a>
            <?php else: ?>
                <a href="Podstorny/login.php">Zaloguj się</a>
            <?php endif; ?>
        </div>
    </div>
</nav>



<div class="Container_zdj_1">
    <div class="left_photo">
            <img src="zdjecia/hema.jpg" alt="Obraz przedstawiający HEMA">
            <p class="l_overlay-text">
                <span class="heading">HEMA</span><br>
                Dawne europejskie sztuki walki,<br>
            Dawne europejskie sztuki walki,<br>
            (ang. Historical European martial arts) – sport walki oparty na badaniu i
            odtwarzaniu dawnych europejskich technik bojowych. Łączy badania historyczne z
            praktyką, odtwarzając tradycyjne style szermierki i walki przy użyciu symulatorów
            broni historycznej, takich jak miecze, szable i inne.
        </p>
            </div>
            <div class="read-more-button">
                <a href="#kim_jestesmy" class="button-link">Czytaj dalej</a>
            </div>


    <div class="right_photo">
            <img src="zdjecia/96b.jpg" alt="Obraz przedstawiający REKO">
            <div class="r_overlay-text">
                <span class="heading">REKO</span><br>
            Grupa rekonstrukcyjna specjalizująca się na wiernym przywracaniu wyglądu, uzbrojenia, formacji
            i stylu życia żołnierzy z XV-XVII wieku. Poprzez staranne odwzorowanie detali oraz badania historyczne
            przybliżają widzom kulturę tamtego okresu.
        </div>
    </div>
</div>

<div class="kim_jestesmy" id="kim_jestesmy">
    <h2>O NAS</h2>
    <p>
        Szermierka Historyczna - klub działający przy Politechnice Lubelskiej jest
        grupą entuzjastów zafascynowanych dawnymi sztukami walki z wykorzystaniem broni białej.
        W obszar naszych zainteresowań wchodzą wszelkie techniki sieczno-kolne wykonywane z użyciem replik broni historycznej.
        Szczególny nacisk kładziemy na kultywowanie najlepszych tradycji polskiego oręża, przede wszystkim walkę szablą husarską.
        Podczas ćwiczeń kierujemy się wskazówkami zawartymi w traktatach dawnych mistrzów oraz współczesnych instruktorów sztuk walki bronią białą.
    </p>
    <p>
        Czynnie działamy w ruchu rekonstrukcyjnym, corocznie biorąc udział w licznych wydarzeniach organizowanych w kraju i za granicą.
        W ramach naszej aktywności najściślej współpracujemy ze Stowarzyszeniem Chorągiew Rycerstwa Ziemi Lubelskiej (CHRZL).
        Dzięki czemu mamy możliwość częstych sparingów, konsultacji i wymiany spostrzeżeń z doświadczonymi szermierzami oraz osobami
        posiadającymi dużą wiedzę z zakresu historii uzbrojenia, ubiorów i dawnych obyczajów. Działalność organizacji obejmuje również
        wyjazdy do muzeów oraz spotkania z entuzjastami historii organizowane w celu poszerzenia zakresu wiedzy, jaką dysponują członkowie klubu.
    </p>
    <p>
        Wszystkie osoby zainteresowane dawnymi sztukami walki bronią białą zapraszamy do współpracy oraz udziału w naszych treningach.
    </p>
</div>

<div class="treningi" id="treningi">
    <h2>TRENINGI</h2>
    <p>
        Trenujemy dwa razy w tygodniu na terenie Politechniki Lubelskiej – we wtorki w godzinach 17:30-20:00 oraz w piątki 17:00-18:30.
        Nie potrzebujesz własnego sprzętu, zapewniamy go na miejscu. Wystarczy, że zabierzesz ze sobą strój sportowy,
        obuwie oraz suspensorium (dla mężczyzn).
    </p>
    <p>
        Jeśli chcesz dołączyć do nas na pierwszy trening,
        wyślij do nas maila, abyśmy mogli przygotować sprzęt. Pierwszy trening jest darmowy, następnie jest pobierana niewielka
        miesięczna składka członkowska.
    </p>
</div>

<div id="map" class="map">
    <section>
        <h2>Znajdź nas tutaj</h2>
        <p>Lublin, Nadbystrzycka 36</p>
        <p>Hala Sportowa Politechniki Lubelskiej oraz "Rdzewiak"<br>
            Wtorki: 17:30-20:00&nbsp; &nbsp;|&nbsp;&nbsp;Piątki: 17:00-18:30
        </p>

        <iframe src="https://www.google.com/maps/embed?pb=!1m14!1m8!1m3!1d502.59015930393815!2d22.551011184025!3d51.23612643109541!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x47225771265bc477%3A0x8ae36897283722d1!2sCentrum%20Innowacji%20i%20Zaawansowanych%20Technologii%20Politechniki%20Lubelskiej!5e1!3m2!1spl!2spl!4v1729432603695!5m2!1spl!2spl"
                width="400" height="450" style="border:0;"
                allowfullscreen="" aria-hidden="false" tabindex="0"></iframe>

        <iframe src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d422.63478309421345!2d22.55264169077926!3d51.235198951365696!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x472257714d035ce5%3A0xcf74c9fa007bec85!2sHala%20Sportowa%20Politechniki%20Lubelskiej!5e1!3m2!1spl!2spl!4v1729003278044!5m2!1spl!2spl"
                width="400" height="450" style="border:0;"
                allowfullscreen="" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
    </section>
</div>

<div class="more">

    <div class="photo-container">
        <img src="zdjecia/traktat.jpg" alt="Zdjęcie 1">
        <div class="hover-text">
            <p class="centered-text">Podstawowy poradnik</p>
            <button class="hover-button">Dowiedz się więcej</button>
        </div>
    </div>

    <div class="photo-container">
        <img src="zdjecia/gear.jpg" alt="Zdjęcie 2">

        <div class="hover-text">
            <p class="centered-text">Sprzęt</p>
            <button class="hover-button">Dowiedz się więcej</button>
        </div>
    </div>

    <div class="photo-container">
        <img src="zdjecia/galeria.jpg" alt="Zdjęcie 3">
        <div class="hover-text">
            <p class="centered-text">Galeria</p>
            <button class="hover-button">Dowiedz się więcej</button>

        </div>
    </div>
</div>
<div id="platnosc" class="user-payment-info">
    <?php if ($is_logged_in): ?>
        <h2>Twoje dane płatności</h2>

        <!-- Najnowsza płatność -->
        <?php if (!empty($payment_history)): ?>
            <div class="latest-payment">
                <h3>Ostatnia płatność</h3>
                <p><strong>Kwota:</strong> <?php echo number_format($payment_history[0]['amount'], 2); ?> PLN</p>
                <p><strong>Data płatności:</strong> <?php echo $payment_history[0]['payment_date'] ? $payment_history[0]['payment_date'] : 'Brak'; ?></p>
                <p><strong>Status:</strong> <?php echo htmlspecialchars($payment_history[0]['payment_status']) ?: 'Brak'; ?></p>
                <p><strong>Termin płatności:</strong> <?php echo $payment_history[0]['due_date'] ? $payment_history[0]['due_date'] : 'Brak'; ?></p>
            </div>

            <!-- menu z historią płatności -->
            <button id="toggleHistory" class="toggle-button">Zobacz historię płatności</button>
            <div id="paymentHistory" class="payment-history" style="display: none;">
                <h3>Historia płatności</h3>
                <ul>
                    <?php foreach ($payment_history as $index => $payment): ?>
                        <?php if ($index > 0): ?> <!-- Pomijamy pierwszą płatność -->
                            <li>
                                <p><strong>Kwota:</strong> <?php echo number_format($payment['amount'], 2); ?> PLN</p>
                                <p><strong>Data płatności:</strong> <?php echo $payment['payment_date'] ? $payment['payment_date'] : 'Brak'; ?></p>
                                <p><strong>Status:</strong> <?php echo htmlspecialchars($payment['payment_status']) ?: 'Brak'; ?></p>
                                <p><strong>Termin płatności:</strong> <?php echo $payment['due_date'] ? $payment['due_date'] : 'Brak'; ?></p>
                            </li>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php else: ?>
            <p><?php echo $subscription_status; ?></p>
        <?php endif; ?>
    <?php else: ?>
        <p>Zaloguj się, aby zobaczyć swoje dane płatności.</p>
    <?php endif; ?>
</div>

<div id="kontakt" class="contact-section">
    <h2>Kontakt</h2>
    <p>Masz pytania? Skontaktuj się z nami!</p>
    <div class="contact-info">
        <p><strong>Email:</strong> kontakt@szermierkahistoryczna.pl</p>
        <p><strong>Adres:</strong> Politechnika Lubelska, ul. Nadbystrzycka 38D, 20-618 Lublin</p>
        <p><strong>Godziny zajęć:</strong> Wtorek: 17:30-20:00 | Piątek: 17:00-18:30 </p>
    </div>
</div>


<footer>
    <p>© 2024 Szermierka historyczna. Wszelkie prawa zastrzeżone.</p>
</footer>


<script>
document.getElementById("toggleHistory").addEventListener("click", function() {
    var paymentHistory = document.getElementById("paymentHistory");
    if (paymentHistory.style.display === "none") {
        paymentHistory.style.display = "block";
        this.textContent = "Zwiń historię płatności";
    } else {
        paymentHistory.style.display = "none";
        this.textContent = "Zobacz historię płatności";
    }
});
</script>


</body>
</html>
