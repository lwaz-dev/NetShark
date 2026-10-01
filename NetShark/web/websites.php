<?php
// websites.php — proxies website/domain monitoring and blocking to Flask.
// Real DNS-level blocking via the hosts file happens on the Python side.

header('Content-Type: application/json');

$flaskBase = 'http://127.0.0.1:5000';
$action = $_GET['action'] ?? '';

function flask_get($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
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

function flask_post($url, $jsonBody) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($jsonBody));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
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
    case 'list':
        $sessionId = intval($_GET['session_id'] ?? 0);
        [$code, $body] = flask_get("$flaskBase/websites/$sessionId");
        break;

    case 'blocked':
        [$code, $body] = flask_get("$flaskBase/domains/blocked");
        break;

    case 'block':
        $input = json_decode(file_get_contents('php://input'), true);
        $domain = $input['domain'] ?? '';
        if ($domain === '') {
            http_response_code(400);
            echo json_encode(['error' => 'domain is required']);
            exit;
        }
        [$code, $body] = flask_post("$flaskBase/domains/block", ['domain' => $domain]);
        break;

    case 'unblock':
        $input = json_decode(file_get_contents('php://input'), true);
        $domain = $input['domain'] ?? '';
        if ($domain === '') {
            http_response_code(400);
            echo json_encode(['error' => 'domain is required']);
            exit;
        }
        [$code, $body] = flask_post("$flaskBase/domains/unblock", ['domain' => $domain]);
        break;

    case 'log':
        $sessionId = intval($_GET['session_id'] ?? 0);
        $after = intval($_GET['after'] ?? 0);
        [$code, $body] = flask_get("$flaskBase/sessions/$sessionId/terminal-log?after=$after");
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'unknown action']);
        exit;
}

http_response_code($code ?: 500);
echo $body ?: json_encode(['error' => 'no response from capture engine']);
