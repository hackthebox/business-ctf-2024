<?php
class Model {
    public function __construct()
    {
        $this->database = Database::getDatabase();
    }
}