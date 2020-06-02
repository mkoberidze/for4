<?php

?>
<form method="post" action="/register">
    <div class="form-group">
        <label for="registeruser">Name</label>
        <input type="text" class="form-control <?php echo isset($errors['registeruser']) ? ' is-invalid' : '' ?>"
               value="<?php if(isset($_SESSION['registeruser'])) echo $_SESSION['registeruser']; else echo "";  ?>" name="registeruser">
        <div class="invalid-feedback">
            <?php echo $errors['registeruser'] ?? '' ?>
        </div>

        <label for="surname">Surname</label>
        <input type="text" class="form-control <?php echo isset($errors['surname']) ? ' is-invalid' : '' ?>" id="surname" name="surname"
               value="<?php if(isset($_SESSION['surname'])) echo $_SESSION['surname']; else echo ""; ?>">
        <div class="invalid-feedback">
            <?php echo $errors['surname'] ?? '' ?>
        </div>

        <label for="email">Email</label>
        <input type="text" class="form-control <?php echo isset($errors['email']) ? ' is-invalid' : '' ?>" id="email" name="email"
               value="<?php if(isset($_SESSION['email'])) echo $_SESSION['email']; else echo ""; ?>">
        <div class="invalid-feedback">
            <?php echo $errors['email'] ?? '' ?>
        </div>


        <label for="passwd">Password</label>
        <input type="password" class="form-control <?php echo isset($errors['passwd']) ? ' is-invalid' : '' ?>" id="passwd" name="passwd"
               value="<?php if(isset($_SESSION['passwd'])) echo $_SESSION['passwd']; else echo ""; ?>">
        <div class="invalid-feedback">
            <?php echo $errors['passwd'] ?? '' ?>
        </div>

        <label for="exampleInputEmail1">Confirm Password</label>
        <input type="password" name="checkpass" class="form-control <?php echo isset($errors['checkpass']) ? ' is-invalid' : '' ?>"
               id="exampleInputEmail1" aria-describedby="emailHelp" placeholder="Enter email">
        <div class="invalid-feedback">
            <?php echo $errors['checkpass'] ?? '' ?>
        </div>


        <button type="submit" id = "sbmt" class="btn btn-primary">Submit</button>
</form>