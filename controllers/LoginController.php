<?php

namespace app\controllers;

use app\IRequest;
use app\Router;

class LoginController
{
    public function renderLogin(IRequest $request, Router $router)
    {
        $router->layout = 'login_layout';
        return $router->renderView('login');
    }

    public function login(IRequest $request, Router $router)
    {
        $data = $request->getBody();
        list($success, $message) = $router->database->login($data['email'], $data['password'], $user);
        if ($success) {
            $_SESSION['currentUser'] = $user;
            header('Location: /');
            exit;
        }
        return $router->renderView('login', [
            'errorMessage' => $message,
            'data' => $data
        ]);
    }

    public function logout(IRequest $request)
    {
        session_destroy();
        header('Location: ' . $request->httpReferer);
        exit;
    }
}