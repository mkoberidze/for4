<?php
namespace app;
use app\controllers\RegisterController;
class Request implements IRequest
{
    public $headers = [];
    public function __construct()
    {
        foreach ($_SERVER as $key => $item) {
            $camelCaseKey = $this->toCamelCase($key);
            $this->{$camelCaseKey} = $item;
        }

        foreach (getallheaders() as $headerName => $value) {
            $this->headers[strtolower($headerName)] = $value;
        }
    }

    public function toCamelCase($string)
    {
        $result = strtolower($string);

        preg_match_all('/_[a-z]/', $result, $matches);
        foreach ($matches[0] as $match) { // _r
            $c = str_replace('_', '', strtoupper($match)); // _r -> _R -> R
            $result = str_replace($match, $c, $result);
        }

        return $result;
    }

    public function getBody()
    {
        if ($this->getMethod() === "get") {
            $body = [];
            foreach ($_GET as $key => $value) {
                $body[$key] = filter_input(INPUT_GET, $key, FILTER_SANITIZE_SPECIAL_CHARS);
            }

            return $body;
        }
        if ($this->getMethod() === "post") {
            $body = [];
            foreach ($_POST as $key => $value) {
                $body[$key] = filter_input(INPUT_POST, $key, FILTER_SANITIZE_SPECIAL_CHARS);
            }

            return $body;
        }
    }

    public function getMethod()
    {
        return strtolower($this->requestMethod);
    }

    public function getPath()
    {
        if (strpos($this->requestUri, '?') !== false) {
            $path = substr($this->requestUri, 0, strpos($this->requestUri, '?'));
        } else {
            $path = $this->requestUri;
        }
        return $path ?: '/';
    }
}