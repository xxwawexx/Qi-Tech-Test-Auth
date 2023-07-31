<?php

require 'vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;

$base_url = "https://api-auth.sandbox.qitech.app";
$endpoint = "/test";
$method = "POST";
$request_body = ["name" => "QI Tech"];

$api_key = "9542a700-71d9-46cc-bcfa-58733d62bc69";
$privateKeyString = "-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBjlDlRkfEdV71GAv58nLYLYQY9jI+nOEeOxVAPVESdc8E0TMELEpg
fGyrRYmijcSUVHSDyNC/mKBQfHZsaft8tmigBwYFK4EEACOhgYkDgYYABAHnVaLR
E0TflvXztz0ReWGZ+Pmhh6NSocwCe1zLp86Z+gIW+2yv/yTKO8Dp6S82bybqLegA
0DkjyP6F6k1SAn85rQDzuHQHS8Rp4r8EihAbeI3rdSAWDaYUudj0xebUJcBa+GeT
99ScKEdoRqaDZm3arLlec7Y/6iDdbywGXkfj1519wA==
-----END EC PRIVATE KEY-----";

$timestamp = gmdate('Y-m-d\TH:i:s.u\Z');

$request_body_json = json_encode($request_body);
$md5_hash = md5($request_body_json);

$algorithmManager = new AlgorithmManager([new ES512()]);
$jwsBuilder = new JWSBuilder($algorithmManager);

$payload = [
    "payload_md5" => $md5_hash,
    "timestamp" => $timestamp,
    "method" => $method,
    "uri" => $endpoint
];

$jwk = JWKFactory::createFromKey($privateKeyString, null, ['alg' => 'ES512', 'use' => 'sig']);

$jws = $jwsBuilder
    ->create()->withPayload(json_encode($payload))
    ->addSignature($jwk, ['alg' => 'ES512', 'typ' => 'JWT'])
    ->build();

$serializer = new CompactSerializer();
$token = $serializer->serialize($jws, 0);

$signed_header = [
    "AUTHORIZATION: Bearer " . $token,
    "API-CLIENT-KEY: " . $api_key
];

$context = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => $signed_header,
        'content' => $request_body_json,
    ],
]);

print_r($signed_header);

$url = $base_url . $endpoint;
$response = file_get_contents($url, false, $context);

if ($response === false) {
    die('Error occurred!');
}

var_dump($response);

?>
