<?php
class ProductController extends Controller {
    public function __construct()
    {
        $this->product = new ProductModel();
        parent::__construct();
    }
}
?>