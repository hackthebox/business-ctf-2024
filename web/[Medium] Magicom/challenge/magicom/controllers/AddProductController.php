<?php
class AddProductController extends ProductController
{
    public function index()
    {
        $this->router->view('addProduct');
    }

    public function add() 
    {
        if (empty($_FILES['image']) || empty($_POST['title']) || empty($_POST['description']))
        {
            header('Location: /addProduct?error=1&message=Fields can\'t be empty.');
            exit;
        }

        $title = $_POST["title"];
        $description = $_POST["description"];
        $image = new ImageModel($_FILES["image"]);

        if($image->isValid()) {

            $mimeType = mime_content_type($_FILES["image"]['tmp_name']);
            $extention = explode('/', $mimeType)[1];
            $randomName = bin2hex(random_bytes(8));
            $secureFilename = "$randomName.$extention";

            if(move_uploaded_file($_FILES["image"]["tmp_name"], "uploads/$secureFilename")) {
                $this->product->insert($title, $description, "uploads/$secureFilename");

                header('Location: /addProduct?error=0&message=Product added successfully.');
                exit;
            }
        } else {
            header('Location: /addProduct?error=1&message=Not a valid image.');
            exit;
        }
    }
}
