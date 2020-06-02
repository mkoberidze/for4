<?php

namespace app\controllers;

use app\IRequest;

class RestController
{
    public function getUsers(IRequest $request)
    {
        echo '<pre>';
        var_dump($request->headers);
        echo '</pre>';
        exit;
        $accept = $request->headers['content-type'] ?? false;
        if (strpos($accept, 'application/xml') !== false){
            return "XML";
        } else if (strpos($accept, 'application/json') !== false) {
            return 'JSON';
        }
        $client = new \GuzzleHttp\Client();
        $response = $client->request('GET', 'https://jsonplaceholder.typicode.com/users');

        header('Content-Type: application/json; charset=UTF-8');
        return $response->getBody();
    }
}