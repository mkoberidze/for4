<?php

namespace app\controllers;


use app\IRequest;
use app\Router;

class JsonPlaceholderController
{
    public function getUsers(IRequest $request, Router $router)
    {
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', 'https://jsonplaceholder.typicode.com/users');

        $users = json_decode($response->getBody(), true);
        return $router->getViewContent('users', [
            'users' => $users
        ]);
    }

    public function getPosts(IRequest $request, Router $router)
    {
        $params = $request->getBody();
        $URL = "https://jsonplaceholder.typicode.com/posts?userId=".$params['userId'];
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', $URL);

        $posts = json_decode($response->getBody(), true);
        return $router->getViewContent('posts', [
            'posts' => $posts
        ]);
    }
}