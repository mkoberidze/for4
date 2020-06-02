<?php
namespace app;

use app\db\Database;

class Router
{
    /**
     * @var \app\IRequest
     */
    public $request = null;
    public $database = null;
    public $routes = [];
    public $postRoutes = [];
    public $layout = 'layout';

    public function __construct(IRequest $request, Database $database)
    {
        $this->request = $request;
        $this->database = $database;
    }

    public function get($path, $callback)
    {
        $this->routes[$path] = $callback;
    }

    public function post($path, $callback)
    {
        $this->postRoutes[$path] = $callback;
    }

    public function __destruct()
    {
        $pathInfo = $this->request->getPath();
        if ($this->request->getMethod() === 'get') {
            $callback = $this->routes[$pathInfo] ?? false;
        } else {
            $callback = $this->postRoutes[$pathInfo] ?? false;
        }

        if (!$callback){
            $content = "404 - Page not found";
        } else {
            if (is_string($callback)){
                echo $this->renderView($callback);
            } else {
                echo call_user_func($callback, $this->request, $this);
            }
        }


    }

    public function getViewContent(string $view, $params = [])
    {
        foreach ($params as $key => $value) {
            $$key = $value;
        }
        /**
         * 123<h1>Home</h1>111
         */
        ob_start();
        include_once __DIR__."/views/{$view}.php";
        return ob_get_clean();
    }

    public function renderView(string $view, $params = [])
    {
        ob_start();
       $content = $this->getViewContent($view, $params);
       include_once __DIR__."/views/{$this->layout}.php";
       return ob_get_clean();
    }

    public function renderContent(string $content)
    {
        ob_start();
        include_once __DIR__."/views/{$this->layout}.php";
        return ob_get_clean();
    }
}