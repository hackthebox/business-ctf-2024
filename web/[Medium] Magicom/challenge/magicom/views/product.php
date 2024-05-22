<?php require 'views/partial/header.php'; ?>
<body>
<div class="container mt-5">
    <div class="row">
        <?php foreach ($data as $product) { ?>
            <div class="col-md-4 mb-4">
                <div class="card custom-card">
                    <img src="<?= $product['image_url']; ?>" class="card-img-top" alt="Product Image">
                    <div class="card-body">
                        <h5 class="card-title"><?= $product['title']; ?></h5>
                        <p class="card-text"><?= $product['description']; ?></p>
                    </div>
                </div>
            </div>
        <?php } ?>
    </div>
</div>
<?php require 'views/partial/footer.php'; ?>