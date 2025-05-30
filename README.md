```
!footer
    <footer>
        <hr>
        <p>Грузовозофф &copy; 2025</p>
    </footer>
</body>
</html>

Header
<!DOCTYPE html>
<html>
<head>
    <title>Грузовозофф - <?= $title ?? '' ?></title>
    <link rel="stylesheet" href="css/style.css"
</head>
<body>
    <h1>Грузовозофф</h1>
    <nav>
        <a href="index.php">Главная</a>
        <?php if (isset($_SESSION['user_id'])): ?>
            | <a href="account.php">Личный кабинет</a>
            <?php if ($_SESSION['is_admin']): ?>
                | <a href="admin.php">Админ-панель</a>
            <?php endif; ?>
        <?php else: ?>
            | <a href="login.php">Войти</a>
        <?php endif; ?>
    </nav>
    <hr>

!Account
<?php
require 'db.php';
checkAuth();

$title = "Личный кабинет";
require './inc/header.php';

$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();

$stmt = $conn->prepare("SELECT id, transport_date, weight, dimensions, cargo_type, from_address, to_address, status 
                       FROM orders WHERE user_id = ? ORDER BY transport_date DESC");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$orders = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
?>

<h2>Личный кабинет</h2>

<div>
    <a href="logout.php"><button>Выйти</button></a>
</div>

<h3>Мои данные</h3>
<p><strong>Логин:</strong> <?= $user['login'] ?></p>
<p><strong>Имя:</strong> <?= $user['name'] ?></p>
<p><strong>Телефон:</strong> <?= $user['phone'] ?></p>
<p><strong>Email:</strong> <?= $user['email'] ?></p>

<h3>Мои заявки</h3>
<?php if (empty($orders)): ?>
    <p>У вас пока нет заявок</p>
    <a href="create_order.php"><button>Создать заявку</button></a>
<?php else: ?>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Дата перевозки</th>
            <th>Вес груза</th>
            <th>Габариты</th>
            <th>Тип груза</th>
            <th>Откуда</th>
            <th>Куда</th>
            <th>Статус</th>
        </tr>
        <?php foreach ($orders as $order): ?>
            <tr>
                <td><?= $order['id'] ?></td>
                <td><?= $order['transport_date'] ?></td>
                <td><?= $order['weight'] ?> кг</td>
                <td><?= $order['dimensions']?></td>
                <td><?= $order['cargo_type'] ?></td>
                <td><?= $order['from_address'] ?></td>
                <td><?= $order['to_address'] ?></td>
                <td><?= $order['status'] ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
    <br>
    <a href="create_order.php"><button>Создать новую заявку</button></a>
<?php endif; ?>

<?php require './inc/footer.php'; ?>

!Admin
<?php
require 'db.php';
checkAdmin();

$title = "Панель администратора";
require './inc/header.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['order_id']) && isset($_POST['status'])) {
    $stmt = $conn->prepare("UPDATE orders SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $_POST['status'], $_POST['order_id']);
    $stmt->execute();
}

$orders = $conn->query("SELECT o.*, u.name, u.phone 
                       FROM orders o JOIN users u ON o.user_id = u.id 
                       ORDER BY o.transport_date DESC")->fetch_all(MYSQLI_ASSOC);
?>

<h2>Панель администратора</h2>

<h3>Все заявки</h3>
<?php if (empty($orders)): ?>
    <p>Нет заявок</p>
<?php else: ?>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Имя</th>
            <th>Телефон</th>
            <th>Дата перевозки</th>
            <th>Вес (кг)</th>
            <th>Габариты</th>
            <th>Тип груза</th>
            <th>Откуда</th>
            <th>Куда</th>
            <th>Статус</th>
            <th>Действия</th>
        </tr>
        <?php foreach ($orders as $order): ?>
            <tr>
                <td><?= $order['id'] ?></td>
                <td><?= $order['name'] ?></td>
                <td><?= $order['phone'] ?></td>
                <td><?= $order['transport_date'] ?></td>
                <td><?= $order['weight'] ?></td>
                <td><?= $order['dimensions'] ?></td>
                <td><?= $order['cargo_type'] ?></td>
                <td><?= $order['from_address'] ?></td>
                <td><?= $order['to_address'] ?></td>
                <td><?= $order['status'] ?></td>
                <td>
                    <form method="post" style="display: inline;">
                        <input type="hidden" name="order_id" value="<?= $order['id'] ?>">
                        <select name="status" onchange="this.form.submit()">
                            <option value="Новая" <?= $order['status'] === 'Новая' ? 'selected' : '' ?>>Новая</option>
                            <option value="В работе" <?= $order['status'] === 'В работе' ? 'selected' : '' ?>>В работе</option>
                            <option value="В пути" <?= $order['status'] === 'В пути' ? 'selected' : '' ?>>В пути</option>
                            <option value="Готово к получению" <?= $order['status'] === 'Готово к получению' ? 'selected' : '' ?>>Готово к получению</option>
                            <option value="Отменена" <?= $order['status'] === 'Отменена' ? 'selected' : '' ?>>Отменена</option>
                        </select>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </table>
<?php endif; ?>

<?php require './inc/footer.php'; ?>

!create_order
<?php
require 'db.php';
checkAuth();

$title = "Создание заявки";
require './inc/header.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $transport_date = $_POST['transport_date'];
    $weight = $_POST['weight'];
    $dimensions = $_POST['dimensions'];
    $cargo_type = $_POST['cargo_type'];
    $from_address = trim($_POST['from_address']);
    $to_address = trim($_POST['to_address']);
    
    if (empty($transport_date)) {
        echo "<script>alert('Укажите дату перевозки');</script>";
    } elseif (empty($weight) || $weight <= 0) {
        echo "<script>alert('Укажите корректный вес груза');</script>";
    } else {
        $stmt = $conn->prepare("INSERT INTO orders (user_id, transport_date, weight, dimensions, cargo_type, from_address, to_address, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Новая')");
        $stmt->bind_param("issssss", $_SESSION['user_id'], $transport_date, $weight, $dimensions, $cargo_type, $from_address, $to_address);
        
        if ($stmt->execute()) {
            echo "<script>alert('Заявка успешно создана!'); window.location.href = 'account.php';</script>";
            exit();
        } else {
            echo "<script>alert('Ошибка при создании заявки');</script>";
        }
    }
}
?>

<h2>Создание новой заявки</h2>
<form method="post">
    <div>
        <label>Дата и время перевозки:</label>
        <input type="datetime-local" name="transport_date" required>
    </div>
    <div>
        <label>Вес груза (кг):</label>
        <input type="number" name="weight" min="1" required>
    </div>
    <div>
        <label>Габариты груза:</label>
        <input type="text" name="dimensions" required>
    </div>
    <div>
        <label>Тип груза:</label>
        <select name="cargo_type" required>
            <option value="хрупкое">Хрупкое</option>
            <option value="скоропортящееся">Скоропортящееся</option>
            <option value="животные">Животные</option>
            <option value="мебель">Мебель</option>
        </select>
    </div>
    <div>
        <label>Адрес отправления:</label>
        <input type="text" name="from_address" required>
    </div>
    <div>
        <label>Адрес доставки:</label>
        <input type="text" name="to_address" required>
    </div>
    <button type="submit">Отправить</button>
</form>
<p><a href="account.php">Вернуться в личный кабинет</a></p>

<?php require './inc/footer.php'; ?>

!db.php
<?php
session_start();


$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'gruzovozoff';


$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


function checkAuth() {
    if (!isset($_SESSION['user_id'])) {
        echo "<script>alert('Необходимо войти в аккаунт'); window.location.href = 'login.php';</script>";
        exit();
    }
}


function checkAdmin() {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo "<script>alert('Доступ запрещен'); window.location.href = 'index.php';</script>";
        exit();
    }
}
?>

!index
<?php
require 'db.php';
$title = "Главная";
require './inc/header.php';
?>

<h2>Добро пожаловать на портал грузоперевозок</h2>
<p>Для оформления заявки необходимо авторизоваться</p>

<?php require './inc/footer.php'; ?>

!login
<?php
require 'db.php';

if (isset($_SESSION['user_id'])) {
    header("Location: account.php");
    exit();
}

$title = "Вход";
require './inc/header.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim($_POST['login']);
    $password = trim($_POST['password']);
    
 
    if ($login === 'admin' && $password === 'gruzovik2024') {
        $_SESSION['user_id'] = 0;
        $_SESSION['is_admin'] = true;
        $_SESSION['login'] = 'admin';
        header("Location: admin.php");
        exit();
    }
    
    
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['is_admin'] = false;
            $_SESSION['login'] = $login;
            header("Location: account.php");
            exit();
        }
    }
    
    echo "<script>alert('Неверный логин или пароль');</script>";
}
?>

<h2>Вход в систему</h2>
<form method="post">
    <div>
        <label>Логин:</label>
        <input type="text" name="login" required>
    </div>
    <div>
        <label>Пароль:</label>
        <input type="password" name="password" required>
    </div>
    <button type="submit">Войти</button>
</form>
<p>Нет аккаунта? <a href="register.php">Зарегистрируйтесь</a></p>

<?php require './inc/footer.php'; ?>

!logout
<?php
require 'db.php';

session_destroy();
header("Location: index.php");
exit();
?>

!register
<?php
require 'db.php';

if (isset($_SESSION['user_id'])) {
    header("Location: account.php");
    exit();
}

$title = "Регистрация";
require './inc/header.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim($_POST['login']);
    $password = trim($_POST['password']);
    $name = trim($_POST['name']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE login = ?");
    $stmt->bind_param("s", $login);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows > 0) {
        echo "<script>alert('Этот логин уже занят');</script>";
    } 

    elseif ($conn->query("SELECT id FROM users WHERE email = '".$conn->real_escape_string($email)."'")->num_rows > 0) {
        echo "<script>alert('Этот email уже используется');</script>";
    }
    elseif (strlen($login) < 6) {
        echo "<script>alert('Логин должен содержать минимум 6 символов');</script>";
    } elseif (strlen($password) < 6) {
        echo "<script>alert('Пароль должен содержать минимум 6 символов');</script>";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Введите корректный email');</script>";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (login, password, name, phone, email) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $login, $hashed_password, $name, $phone, $email);
        
        if ($stmt->execute()) {
            echo "<script>alert('Регистрация успешна!'); window.location.href = 'login.php';</script>";
            exit();
        } else {
            echo "<script>alert('Ошибка при регистрации');</script>";
        }
    }
}
?>

<h2>Регистрация</h2>
<form method="post">
    <div>
        <label>ФИО:</label>
        <input type="text" name="name" required>
    </div>
    <div>
        <label>Логин:</label>
        <input type="text" name="login" required minlength="6">
    </div>
    <div>
        <label>Телефон:</label>
        <input type="text" name="phone" required>
    </div>
    <div>
        <label>Email:</label>
        <input type="email" name="email" required>
    </div>
    <div>
        <label>Пароль:</label>
        <input type="password" name="password" required minlength="6">
    </div>
    <button type="submit">Зарегистрироваться</button>
</form>
<p>Уже есть аккаунт? <a href="login.php">Войдите</a></p>

<?php require './inc/footer.php'; ?>


```
