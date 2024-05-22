<?php
class ProductViewController extends ProductController
{
    public function index()
    {
        $this->router->view('product', $this->product->get());
    }
}
