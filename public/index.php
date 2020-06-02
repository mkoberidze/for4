<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../helpers.php';

use app\controllers\HomeController;
use app\controllers\JsonPlaceholderController;
use app\controllers\LoginController;
use app\controllers\RestController;
use app\controllers\RegisterController;
use app\Router;
use app\Request;
use app\db\Database;

session_start();

$database = new Database();

$router = new Router(new Request(), $database);

$router->get('/', 'index');
$router->get('/json/users', [JsonPlaceholderController::class, 'getUsers']);
$router->get('/json/posts', [JsonPlaceholderController::class, 'getPosts']);

$router->get('/api/users', [RestController::class, 'getUsers']);

$router->get('/about', 'about');

$router->get('/login', [LoginController::class, 'renderLogin']);
$router->post('/login', [LoginController::class, 'login']);
$router->post('/logout', [LoginController::class, 'logout']);

$router->get('/private', [HomeController::class, 'private']);
$router->get('/contact', [HomeController::class, 'contact']);
$router->post('/contact', [HomeController::class, 'postContact']);
$router->get('/register','register');
$router->post('/register', [RegisterController::class,'register']);
