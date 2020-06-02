<?php

function getCurrentUser()
{
    return $_SESSION['currentUser'] ?? false;
}