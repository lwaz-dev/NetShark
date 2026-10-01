<?php
// upload.php — forwards an uploaded .pcap file to the Flask /import endpoint.

header('Content-Type: application/json');

if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['error' => 'no file uploaded, or upload failed']);
    exit;
}

$flaskUrl = 'http://127.0.0.1:5000/import';

$cfile = new CURLFile(
    $_FILES['file']['tmp_name'],
    $_FILES['file']['type'] ?: 'application/octet-stream',
    $_FILES['file']['name']
);

$ch = curl_init($flaskUrl);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, ['file' => $cfile]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 60); // large pcaps can take a while to parse

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
