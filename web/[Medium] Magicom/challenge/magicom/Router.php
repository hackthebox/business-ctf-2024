<?php

class Router {
    private $routes = [];

    public function get($path, $callback) {
        $this->routes['GET'][$path] = $callback;
    }

    public function post($path, $callback) {
        $this->routes['POST'][$path] = $callback;
    }

    public function view($view, $data = []) {
        require_once 'views/' . $view . '.php';
    }

    public function resolve() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

        if (isset($this->routes[$method][$path])) {
            $callback = $this->routes[$method][$path];
            if (is_callable($callback)) {
                return call_user_func($callback);
            } else {
                $callback = explode('@', $callback);
                $controller = new $callback[0]();
                $controller->{$callback[1]}();
                return;
            }
        }

        http_response_code(404);
        $this->view("404");
    }
}