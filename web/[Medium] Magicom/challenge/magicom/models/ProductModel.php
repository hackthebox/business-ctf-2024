<?php

class ProductModel extends Model
{
    public function get()
    {
        $result = $this->database->query('SELECT title, description, image_url FROM products');
        $products = array();
        
        while ($product = $result->fetch_assoc()) {
            $title = htmlspecialchars($product['title'], ENT_QUOTES, 'UTF-8');
            $description = htmlspecialchars($product['description'], ENT_QUOTES, 'UTF-8');
            $image_url = htmlspecialchars($product['image_url'], ENT_QUOTES, 'UTF-8');
        
            $products[] = array(
                'title' => $title,
                'description' => $description,
                'image_url' => $image_url
            );
        }

        return $products;
    }

    public function insert($title, $description, $image_url)
    {
        $this->database->query('INSERT INTO products (title, description, image_url) VALUES(?,?,?)', [
            's' => [$title, $description, $image_url]
        ]);
    }
}
