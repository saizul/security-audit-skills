<?php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
echo $_GET['name'];
system("convert " . $file);
include $_GET['page'] . '.php';
$data = unserialize($_COOKIE['cart']);
$body = file_get_contents($_GET['url']);
header("Location: " . $_GET['next']);
