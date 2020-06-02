<?php
$errors = $errors ?? [];
$data = $data ?? [];

?>

<div class="container">
    <h1>Contact</h1>
    <form action="/contact" method="post">
        <div class="form-group">
            <label for="exampleInputEmail1">Email address</label>
            <input type="email" class="form-control" id="exampleInputEmail1"
                   name="email">
        </div>
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</div>