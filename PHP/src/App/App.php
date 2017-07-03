<?php

namespace App;

class App
{
    private $app;

    public function __construct()
    {
        $settings =  require __DIR__."/../settings.php";

        $app = new \Slim\App($settings);

        require __DIR__ . '/../dependencies.php';
        require __DIR__ . '/../middleware.php';
        require __DIR__ . '/../routes.php';

        $this->app = $app;
    }

    public function get()
    {
        return $this->app;
    }

}
