<?php
// api.php — proxies read requests to the Python Flask API (127.0.0.1:5000)
// so the browser only ever talks to PHP, never directly to Flask.

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

switch ($action) {
    case 'interfaces':
        [$code, $body] = flask_get("$flaskBase/interfaces");
        break;

    case 'live_status':
        [$code, $body] = flask_get("$flaskBase/live/status");
        break;

    case 'sessions':
        [$code, $body] = flask_get("$flaskBase/sessions");
        break;

    case 'packets':
        $sessionId = intval($_GET['session_id'] ?? 0);
        $params = array_filter([
            'page'     => intval($_GET['page'] ?? 1),
            'per_page' => intval($_GET['per_page'] ?? 50),
            'protocol' => $_GET['protocol'] ?? null,
            'src_ip'   => $_GET['src_ip'] ?? null,
            'dst_ip'   => $_GET['dst_ip'] ?? null,
        ], fn($v) => $v !== null && $v !== '');
        $query = http_build_query($params);
        [$code, $body] = flask_get("$flaskBase/sessions/$sessionId/packets?$query");
        break;

    case 'packet_detail':
        $sessionId = intval($_GET['session_id'] ?? 0);
        $packetNumber = intval($_GET['packet_number'] ?? 0);
        [$code, $body] = flask_get("$flaskBase/sessions/$sessionId/packets/$packetNumber");
        break;

    case 'hosts':
        $sessionId = intval($_GET['session_id'] ?? 0);
        [$code, $body] = flask_get("$flaskBase/sessions/$sessionId/hosts");
        break;

    case 'statistics':
        $sessionId = intval($_GET['session_id'] ?? 0);
        [$code, $body] = flask_get("$flaskBase/sessions/$sessionId/statistics");
        break;

    default:
        http_response_code(400);
        echo json_encode(['error' => 'unknown action']);
        exit;
}

http_response_code($code ?: 500);
echo $body ?: json_encode(['error' => 'no response from capture engine']);
