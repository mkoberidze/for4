<?php
namespace app;

interface IRequest
{
    public function getBody();

    public function getMethod();

    public function getPath();
}