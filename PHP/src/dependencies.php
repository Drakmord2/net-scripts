<?php

// DIC configuration
use \Interop\Container\ContainerInterface;

$container = $app->getContainer();

// -----------------------------------------------------------------------------
// Action factories
// -----------------------------------------------------------------------------

$container["jwt"] = function ( ContainerInterface $container) {
    return new StdClass();
};
