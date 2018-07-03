<?php
//
// +---------------------------------------------------------------------+
// | CODE INC. SOURCE CODE                                               |
// +---------------------------------------------------------------------+
// | Copyright (c) 2018 - Code Inc. SAS - All Rights Reserved.           |
// | Visit https://www.codeinc.fr for more information about licensing.  |
// +---------------------------------------------------------------------+
// | NOTICE:  All information contained herein is, and remains the       |
// | property of Code Inc. SAS. The intellectual and technical concepts  |
// | contained herein are proprietary to Code Inc. SAS are protected by  |
// | trade secret or copyright law. Dissemination of this information or |
// | reproduction of this material is strictly forbidden unless prior    |
// | written permission is obtained from Code Inc. SAS.                  |
// +---------------------------------------------------------------------+
//
// Author:   Joan Fabrégat <joan@codeinc.fr>
// Date:     03/07/2018
// Time:     11:40
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\AuthTokenStorage;
use CodeInc\GoogleOAuth2Middleware\AuthToken;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class SessionStorageDriver
 *
 * @package CodeInc\GoogleOAuth2Middleware\AuthTokenStorage
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class SessionStorageDriver implements AuthTokenStorageDriverInterface
{
    public const DEFAULT_SESSION_KEY = '__authToken';

    /**
     * @var string
     */
    private $sessionKey;

    /**
     * SessionStorageDriver constructor.
     *
     * @param string $sessionKey
     */
    public function __construct(string $sessionKey = self::DEFAULT_SESSION_KEY)
    {
        $this->setSessionKey($sessionKey);
    }

    /**
     * @return string
     */
    public function getSessionKey():string
    {
        return $this->sessionKey;
    }

    /**
     * @param string $sessionKey
     */
    public function setSessionKey(string $sessionKey):void
    {
        if (empty($sessionKey)) {
            throw new InvalidArgumentException("The session key can not be empty");
        }
        $this->sessionKey = $sessionKey;
    }

    /**
     * @inheritdoc
     * @param AuthToken $token
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function saveAuthToken(AuthToken $token, ResponseInterface $response):ResponseInterface
    {
        $_SESSION[$this->sessionKey] = $token;
        return $response;
    }

    /**
     * @inheritdoc
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function deleteAuthToken(ResponseInterface $response):ResponseInterface
    {
        unset($_SESSION[$this->sessionKey]);
        return $response;
    }

    /**
     * @inheritdoc
     * @param ServerRequestInterface $request
     * @return AuthToken|null
     */
    public function getAuthToken(ServerRequestInterface $request):?AuthToken
    {
        if (isset($_SESSION[$this->sessionKey]) && $_SESSION[$this->sessionKey] instanceof AuthToken) {
            return $_SESSION[$this->sessionKey];
        }
        return null;
    }
}