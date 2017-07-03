<?php

namespace App\Controller;

use Interop\Container\ContainerInterface;

class Controller {

    protected $ci;
    protected $jwt;
    protected $key;

    public function __construct(ContainerInterface $ci) {
        $this->ci = $ci;
        try{
            $this->jwt = $this->ci->get("jwt");
            $this->key = $this->ci["settings"]['key_secret'];
            
        }catch (\Exception $e){
            echo "Error: ".$e->getMessage();
        }

    }

}
