<?php
class HomeController extends Controller
{
    public function index()
    {
        $this->router->view('home');
    }
}
