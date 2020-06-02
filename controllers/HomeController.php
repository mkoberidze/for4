<?php

namespace app\controllers;

use app\IRequest;
use app\Router;

class HomeController
{
    public function contact(IRequest $request, Router $router)
    {
        return $router->renderView('contact', [
            'errors' => [],
            'data' => []
        ]);
    }

    public function postContact(IRequest $request, Router $router)
    {
        // Simulate email sending
        $data = $request->getBody();
        $email = $data['email'];
        $errors = [];
        if (!$email) {
            $errors['email'] = 'გთხოვთ შეავსოთ ეს ველი';
        }

        return $router->renderView('contact', [
            'errors' => $errors,
            'data' => $data
        ]);
    }

    public function private(IRequest $request, Router $router)
    {
        if (!getCurrentUser()) {
            return $router->renderContent("You don't have permission");
        }

        // Do what is necessary
    }
}