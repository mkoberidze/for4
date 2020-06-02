<?php

?>

<table class="table">
    <?php foreach ($users as $user): ?>
        <tr>
            <td><?php echo $user['name'] ?></td>
            <td><?php echo $user['email'] ?></td>
            <td><?php echo $user['phone'] ?></td>
            <td><?php echo $user['website'] ?></td>
            <td>
                <a href="/json/posts?userId=<?php echo $user['id'] ?>">Users Posts</a>
            </td>
        </tr>
    <?php endforeach; ?>
</table>
