<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_GET['id']]);
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$data = json_decode($raw, true);
