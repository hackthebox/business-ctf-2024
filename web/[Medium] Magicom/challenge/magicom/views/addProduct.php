<?php require 'views/partial/header.php'; ?>
<body>
<div class="container mt-5">
    <?php if (isset($_GET['message']) && isset($_GET['error'])): ?>
        <hr><p class='<?php echo $_GET['error'] ? "alert failed" : "alert"; ?>'>
        <?= htmlspecialchars($_GET['message']) ?>
    </p>
    <?php endif; ?>
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card-body">
                <h2 class="mb-5">Add Product</h2>
                <form action="/addProduct" method="post" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label for="title" class="form-label">Product Name</label>
                        <input type="text" class="form-control no-background" id="title" name="title" required>
                    </div>
                    <div class="mb-3">
                        <label for="description" class="form-label">Description</label>
                        <textarea class="form-control no-background" id="description" name="description" rows="3" required></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="image" class="form-label">Image</label>
                        <input type="file" class="form-control no-background" id="image" name="image" required>
                    </div>
                    <button type="submit" class="btn btn-primary btn-hacker">Submit</button>
                </form>
            </div>
        </div>
    </div>
</div>
<?php require 'views/partial/footer.php'; ?>