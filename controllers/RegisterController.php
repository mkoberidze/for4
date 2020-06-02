<?php


namespace app\controllers;


use app\db\database;
use app\Router;

class RegisterController
{
    public function register(\app\IRequest $request,Router $router)
    {
        $data = $request->getBody();
        $errors = [];
        define('REQUIRED_FIELD_ERROR', 'This field is required');
        $data = $request->getBody();

        $errors = [];

        function monthConvert($month){
            if($month == 'January') return '01';
            if($month == 'February') return '02';
            if($month == 'March') return '03';
            if($month == 'April') return '04';
            if($month == 'May') return '05';
            if($month == 'June') return '06';
            if($month == 'July') return '07';
            if($month == 'August') return '08';
            if($month == 'September') return '09';
            if($month == 'October') return '10';
            if($month == 'November') return '11';
            if($month == 'December') return '12';
        }
        function alert($msg) {
            echo "<script type='text/javascript'>alert('$msg');</script>";
        }
        if (!$data['registeruser']){
            $errors['registeruser'] = REQUIRED_FIELD_ERROR;
        }

        if (!$data['surname']){
            $errors['surname'] = REQUIRED_FIELD_ERROR;
        }

        if (!$data['email']) {
            $errors['email'] = REQUIRED_FIELD_ERROR;
        } elseif (strpos($data['email'], '@') !== false) {
            echo "";
        } else $errors['email'] = "Not valid Email";

        if(!$data['passwd']){
            $errors['passwd'] = REQUIRED_FIELD_ERROR;
        } elseif (strlen($data['passwd'])<6) {
            $errors['passwd'] = "Password should contain more than 6 character";
        }

        if(!$data['checkpass']) {
            $errors['checkpass'] = REQUIRED_FIELD_ERROR;
        }

        if($data['checkpass'] != $data['passwd']) {
            $errors['passwd'] = "Passwords Doesn't match";
            $errors['checkpass'] = "Passwords Doesn't match";
        }
        $_SESSION['registeruser'] = $data['registeruser'];
        $_SESSION['surname'] = $data['surname'];
        $_SESSION['email'] = $data['email'];

        $params = [
            'errors' => $errors,
            'data' => $data
        ];

        if(empty($errors)){
            $info = new database();
            $info->insertUser($data['registeruser'],$data['surname'],$data['email'],password_hash($data['passwd'],PASSWORD_BCRYPT));
            return $router->renderView('home',$params);
        } else return $router->renderView('register',$params);
    }


}