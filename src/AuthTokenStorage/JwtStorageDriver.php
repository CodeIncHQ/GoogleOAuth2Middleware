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
// Time:     11:27
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\AuthTokenStorage;
use CodeInc\GoogleOAuth2Middleware\AuthToken;
use Firebase\JWT\JWT;
use HansOtt\PSR7Cookies\SetCookie;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class AuthTokenJwtStorage
 *
 * @package CodeInc\GoogleOAuth2Middleware\AuthTokenStorage
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class JwtStorageDriver implements AuthTokenStorageDriverInterface
{
    // see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
    const DEFAULT_JWT_ALGO = 'HS256';

    // auth cookie default settings
    const DEFAULT_AUTH_COOKIE_NAME = '__auth';
    const DEFAULT_AUTH_COOKIE_SECURE = false;
    const DEFAULT_AUTH_COOKIE_HTTP_ONLY = false;

    /**
     * Name of the auth cookie
     *
     * @var string
     */
    private $authCookieName = self::DEFAULT_AUTH_COOKIE_NAME;

    /**
     * Cookies domain
     *
     * @var string|null
     */
    private $authCookieDomain;

    /**
     * Cookies path.
     *
     * @var string|null
     */
    private $authCookiePath;

    /**
     * Cookies secure.
     *
     * @var bool
     */
    private $authCookieSecure = self::DEFAULT_AUTH_COOKIE_SECURE;

    /**
     * Cookies HTTP only.
     *
     * @var bool
     */
    private $authCookieHttpOnly = self::DEFAULT_AUTH_COOKIE_HTTP_ONLY;


    /**
     *JSON web token encryption key.
     *
     * @var string
     */
    private $jwtKey;

    /**
     * JSON web token encryption algorithme.
     *
     * @var string
     */
    private $jwtAlgo;

    /**
     * AuthTokenJwtStorage constructor.
     *
     * @param string $jwtKey
     * @param string $jwtAlgo
     */
    public function __construct(string $jwtKey, string $jwtAlgo = self::DEFAULT_JWT_ALGO)
    {
        $this->jwtKey = $jwtKey;
        $this->jwtAlgo = $jwtAlgo;
    }

    /**
     * @inheritdoc
     * @param AuthToken $authToken
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws \ReflectionException
     */
    public function saveAuthToken(AuthToken $authToken, ResponseInterface $response):ResponseInterface
    {
        return SetCookie::thatExpires(
            $this->authCookieName,
            JWT::encode($authToken->toArray(), $this->jwtKey, $this->jwtAlgo),
            $authToken->getExpiresAt(),
            $this->authCookiePath ?? '',
            $this->authCookieDomain ?? '',
            $this->authCookieSecure,
            $this->authCookieHttpOnly
        )->addToResponse($response);
    }

    /**
     * @inheritdoc
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function deleteAuthToken(ResponseInterface $response):ResponseInterface
    {
        return SetCookie::thatDeletesCookie(
            $this->authCookieName,
            $this->authCookiePath ?? '',
            $this->authCookieDomain ?? '',
            $this->authCookieSecure,
            $this->authCookieHttpOnly
        )->addToResponse($response);
    }

    /**
     * @inheritdoc
     * @param ServerRequestInterface $request
     * @return AuthToken|null
     * @throws \CodeInc\GoogleOAuth2Middleware\AuthTokenException
     * @throws \ReflectionException
     */
    public function getAuthToken(ServerRequestInterface $request):?AuthToken
    {
        if (isset($request->getCookieParams()[$this->authCookieName]))
        {
            // decoding the auth cookie
            $authToken = JWT::decode(
                $request->getCookieParams()[$this->authCookieName],
                $this->jwtKey,
                [$this->jwtAlgo]
            );

            // if the auth cookie contains a valid auth token
            if (isset($authToken->googleId) && is_numeric($authToken->googleId)) {
                return AuthToken::fromArray((array)$authToken);
            }
        }
        return null;
    }

    /**
     * @return string
     */
    public function getJwtAlgo():string
    {
        return $this->jwtAlgo;
    }

    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
     * @param string $jwtAlgo
     */
    public function setJwtAlgo(string $jwtAlgo):void
    {
        $this->jwtAlgo = $jwtAlgo;
    }

    /**
     * @return string|null
     */
    public function getAuthCookieDomain():?string
    {
        return $this->authCookieDomain;
    }

    /**
     * @param string $authCookieDomain
     */
    public function setAuthCookieDomain(string $authCookieDomain):void
    {
        $this->authCookieDomain = $authCookieDomain;
    }

    /**
     * @return string|null
     */
    public function getAuthCookiePath():string
    {
        return $this->authCookiePath;
    }

    /**
     * @return bool
     */
    public function getAuthCookieHttpOnly():bool
    {
        return $this->authCookieHttpOnly;
    }

    /**
     * @param bool $authCookieHttpOnly
     */
    public function setAuthCookieHttpOnly(bool $authCookieHttpOnly):void
    {
        $this->authCookieHttpOnly = $authCookieHttpOnly;
    }

    /**
     * @return bool
     */
    public function getAuthCookieSecure():bool
    {
        return $this->authCookieSecure;
    }

    /**
     * @param bool $authCookieSecure
     */
    public function setAuthCookieSecure(bool $authCookieSecure):void
    {
        $this->authCookieSecure = $authCookieSecure;
    }

    /**
     * @param string $authCookiePath
     */
    public function setAuthCookiePath(string $authCookiePath):void
    {
        $this->authCookiePath = $authCookiePath;
    }

    /**
     * @return string
     */
    public function getAuthCookieName():string
    {
        return $this->authCookieName;
    }

    /**
     * @param string $authCookieName
     */
    public function setAuthCookieName(string $authCookieName):void
    {
        $this->authCookieName = $authCookieName;
    }

    /**
     * @return string
     */
    public function getJwtKey():string
    {
        return $this->jwtKey;
    }
}