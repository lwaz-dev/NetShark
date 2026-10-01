<?php
// scan.php — proxies an active nmap scan request to Flask.
// POST with JSON body {"ip": "192.168.1.5"}. Can take 10-30+ seconds.

header('Content-Type: application/json');

$flaskBase = 'http://127.0.0.1:5000';

$input = json_decode(file_get_contents('php://input'), true);
$ip = $input['ip'] ?? '';

if ($ip === '') {
    http_response_code(400);
    echo json_encode(['error' => 'ip is required']);
    exit;
}

$ch = curl_init("$flaskBase/scan");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['ip' => $ip]));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 60); // nmap scans can be slow

$response = curl_exec($ch);

if (curl_errno($ch)) {
    $error = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    echo json_encode(['error' => "could not reach capture engine: $error"]);
    exit;
}

$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

http_response_code($httpCode);
echo $response;
