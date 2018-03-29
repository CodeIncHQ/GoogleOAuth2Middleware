<?php
//
// +---------------------------------------------------------------------+
// | CODE INC. SOURCE CODE                                               |
// +---------------------------------------------------------------------+
// | Copyright (c) 2017 - Code Inc. SAS - All Rights Reserved.           |
// | Visit https://www.codeinc.fr for more information about licensing.  |
// +---------------------------------------------------------------------+
// | NOTICE:  All information contained herein is, and remains the       |
// | property of Code Inc. SAS. The intellectual and technical concepts  |
// | contained herein are proprietary to Code Inc. SAS are protected by  |
// | trade secret or copyright law. Dissemination of this information or |
// | reproduction of this material  is strictly forbidden unless prior   |
// | written permission is obtained from Code Inc. SAS.                  |
// +---------------------------------------------------------------------+
//
// Author:   Joan Fabrégat <joan@codeinc.fr>
// Date:     28/03/2018
// Time:     16:43
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware;
use Throwable;

/**
 * Class GoogleOAuth2MiddlewareException
 *
 * @package CodeInc\GoogleOAuth2Middleware
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class GoogleOAuth2MiddlewareException extends \Exception
{
    /**
     * @var GoogleOAuth2Middleware
     */
    private $middleware;

    /**
     * GoogleOauth2MiddlewareException constructor.
     *
     * @param string $message
     * @param GoogleOAuth2Middleware $middleware
     * @param int $code
     * @param null|Throwable $previous
     */
    public function __construct(string $message, GoogleOAuth2Middleware $middleware, int $code = 0, ?Throwable $previous = null)
    {
        $this->middleware = $middleware;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return GoogleOAuth2Middleware
     */
    public function getMiddleware():GoogleOAuth2Middleware
    {
        return $this->middleware;
    }
}