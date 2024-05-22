<?php

spl_autoload_register(function ($name) {
    $parts = explode('\\', $name);
    $className = array_pop($parts);
    if (preg_match('/Controller$/', $name)) {
        $name = 'controllers/' . $name;
    }

    if (preg_match('/Model$/', $name)) {
        $name = 'models/' . $name;
    }

    $file = $name . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});

$database = new Database('localhost', 'beluga', 'beluga', 'magicom');
$database->connect();

$router = new Router;

$router->get('/', 'HomeController@index');
$router->get('/home', 'HomeController@index');
$router->get('/product', 'ProductViewController@index');
$router->get('/addProduct', 'AddProductController@index');
$router->post('/addProduct', 'AddProductController@add');
$router->get('/info', function(){
    return phpinfo();
});

$router->resolve();
?>
