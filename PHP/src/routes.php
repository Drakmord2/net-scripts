<?php

// Routes

$app->options('/{routes:.+}', function ($request, $response, $args) {
    return $response;
});

$app->get('/info', function ($request, $response, $args) {
    phpinfo();
});

//API
$app->group('/api', function () {

    $this->options('/{routes:.+}', function ($request, $response, $args) {
        return $response;
    });

});
