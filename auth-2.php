<?php

require 'vendor/autoload.php';

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;

$base_url = "https://api-auth.sandbox.qitech.app";
$endpoint = "/test";
$method = "POST";
$request_body = ["name" => "QI Tech"];

$api_key = "9542a700-71d9-46cc-bcfa-58733d62bc69";
$privateKeyString = <<<EOD
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBjlDlRkfEdV71GAv58nLYLYQY9jI+nOEeOxVAPVESdc8E0TMELEpg
fGyrRYmijcSUVHSDyNC/mKBQfHZsaft8tmigBwYFK4EEACOhgYkDgYYABAHnVaLR
E0TflvXztz0ReWGZ+Pmhh6NSocwCe1zLp86Z+gIW+2yv/yTKO8Dp6S82bybqLegA
0DkjyP6F6k1SAn85rQDzuHQHS8Rp4r8EihAbeI3rdSAWDaYUudj0xebUJcBa+GeT
99ScKEdoRqaDZm3arLlec7Y/6iDdbywGXkfj1519wA==
-----END EC PRIVATE KEY-----
EOD;

$timestamp = gmdate('Y-m-d\TH:i:s.u\Z');

$request_body_json = json_encode($request_body);
$md5_hash = md5($request_body_json);

$config = Configuration::forSymmetricSigner(new Sha512(), InMemory::plainText($privateKeyString));

$token = $config->builder()
    ->withClaim('payload_md5', $md5_hash)
    ->withClaim('timestamp', $timestamp)
    ->withClaim('method', $method)
    ->withClaim('uri', $endpoint)
    ->getToken($config->signer(), $config->signingKey());

$signed_header = [
    "AUTHORIZATION: Bearer " . $token->toString(),
    "API-CLIENT-KEY: " . $api_key
];

print_r($signed_header);

$context = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => $signed_header,
        'content' => $request_body_json,
    ],
]);

$url = $base_url . $endpoint;
$response = file_get_contents($url, false, $context);

if ($response === false) {
    die('Error occurred!');
}

var_dump($response);

?>
