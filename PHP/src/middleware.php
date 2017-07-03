<?php

// Application middleware

$arrConfig = [
    "secret" => $container["settings"]['key_secret'],

    "callback" => function (\Slim\Http\Request $request, \Slim\Http\Response $response, $arguments) use ($container) {
        $container["jwt"] = $arguments["decoded"];
    },

    "error" => function ($request, \Slim\Http\Response $response, $arguments) {
        $data["status"] = "error";
        $data["message"] = $arguments["message"];
        return $response
            ->withHeader("Content-Type", "application/json")
            ->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    },

    "rules" => [
        new \Slim\Middleware\JwtAuthentication\RequestPathRule([
            "path" => "/",
            "passthrough" => ["/api/login"]
        ]),
        new \Slim\Middleware\JwtAuthentication\RequestMethodRule([
            "passthrough" => ["OPTIONS"]
        ])
    ]
];

$corsConfig = function ($req, $res, $next) {
    $response = $next($req, $res);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
};

$app->add(new \Slim\Middleware\JwtAuthentication($arrConfig));

$app->add($corsConfig);
