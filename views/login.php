<?php
$errorMessage = $errorMessage ?? false;
$data = $data ?? ['email' => ''];
?>
<div class="container">
    <form action="/login" method="post">
        <?php if ($errorMessage): ?>
            <div class="alert alert-danger">
                <?php echo $errorMessage ?>
            </div>
        <?php endif; ?>
        <div class="form-group">
            <label>Email address</label>
            <input type="email" class="form-control" name="email" value="<?php echo $data['email'] ?>"/>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" class="form-control" name="password"/>
        </div>
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</div>
