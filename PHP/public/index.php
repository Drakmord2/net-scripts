<?php

ini_set('display_errors','Off');

if (PHP_SAPI === 'cli-server' && $_SERVER['SCRIPT_FILENAME'] !== __FILE__) {
    return false;
}

require __DIR__ . '/../vendor/autoload.php';

session_start();

$slim   = new \App\App();
$app    = $slim->get();

$app->run();
