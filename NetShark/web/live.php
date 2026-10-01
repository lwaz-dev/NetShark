<?php
// live.php — proxies start/stop live-capture requests to Flask.
// Expects ?action=start (with JSON body {"interface": "..."}) or ?action=stop.

header('Content-Type: application/json');

$flaskBase = 'http://127.0.0.1:5000';
$action = $_GET['action'] ?? '';

function flask_post($url, $jsonBody = null) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    if ($jsonBody !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($jsonBody));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    }

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        $error = curl_error($ch);
        curl_close($ch);
        return [502, json_encode(['error' => "could not reach capture engine: $error"])];
    }

    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$httpCode, $response];
}

switch ($action) {
    case 'start':
        $input = json_decode(file_get_contents('php://input'), true);
        $interface = $input['interface'] ?? '';
        if ($interface === '') {
            http_response_code(400);
            echo json_encode(['error' => 'interface is required']);
            exit;
        }
        [$code, $body] = flask_post("$flaskBase/live/start", ['interface' => $interface]);
        break;

    case 'stop':
        [$code, $body] = flask_post("$flaskBase/live/stop");
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'unknown action']);
        exit;
}

http_response_code($code ?: 500);
echo $body ?: json_encode(['error' => 'no response from capture engine']);
