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
// Date:     29/03/2018
// Time:     09:34
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware;
use CodeInc\GoogleOAuth2Middleware\Responses\LogoutResponseInterface;
use CodeInc\Psr7Responses\RedirectResponse;
use CodeInc\Url\Url;
use Firebase\JWT\JWT;
use HansOtt\PSR7Cookies\SetCookie;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;


/**
 * Class GoogleOAuth2Middleware
 *
 * @package CodeInc\GoogleOAuth2Middleware
 * @license MIT
 * @link https://github.com/CodeIncHQ/GoogleOAuth2Middleware
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class GoogleOAuth2Middleware implements MiddlewareInterface
{
    // auth cookie default settings
    const DEFAULT_AUTH_COOKIE_NAME = '__auth';
    const DEFAULT_AUTH_COOKIE_SECURE = false;
    const DEFAULT_AUTH_COOKIE_HTTP_ONLY = false;

    // other default settings
    const DEFAULT_AUTH_EXPIRE = '30 minutes';
    const DEFAULT_JWT_ALGO = 'HS256'; // see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
    const DEFAULT_REQUEST_ATTR_NAME = 'auth';

    /**
     * Publis URLs path
     *
     * @see GoogleOAuth2Middleware::addPublicPath()
     * @var array
     */
    private $publicPaths = [];

    /**
     * Name of the auth cookie
     *
     * @see GoogleOAuth2Middleware::setAuthCookieName()
     * @see GoogleOAuth2Middleware::getAuthCookieName()
     * @var string
     */
    private $authCookieName = self::DEFAULT_AUTH_COOKIE_NAME;

    /**
     * Cookies domain
     *
     * @see GoogleOAuth2Middleware::setAuthCookieDomain()
     * @see GoogleOAuth2Middleware::getAuthCookieDomain()
     * @var string|null
     */
    private $authCookieDomain;

    /**
     * Cookies path.
     *
     * @see GoogleOAuth2Middleware::setAuthCookiePath()
     * @see GoogleOAuth2Middleware::getAuthCookiePath()
     * @var string|null
     */
    private $authCookiePath;

    /**
     * Cookies secure.
     *
     * @see GoogleOAuth2Middleware::setAuthCookieSecure()
     * @see GoogleOAuth2Middleware::getAuthCookieSecure()
     * @see GoogleOAuth2Middleware::DEFAULT_AUTH_COOKIE_SECURE
     * @var bool
     */
    private $authCookieSecure = self::DEFAULT_AUTH_COOKIE_SECURE;

    /**
     * Cookies HTTP only.
     *
     * @see GoogleOAuth2Middleware::setAuthCookieHttpOnly()
     * @see GoogleOAuth2Middleware::getAuthCookieHttpOnly()
     * @see GoogleOAuth2Middleware::DEFAULT_AUTH_COOKIE_HTTP_ONLY
     * @var bool
     */
    private $authCookieHttpOnly = self::DEFAULT_AUTH_COOKIE_HTTP_ONLY;

    /**
     * Auth expire.
     *
     * @see GoogleOAuth2Middleware::setAuthExpire()
     * @see GoogleOAuth2Middleware::getAuthExpire()
     * @var \DateInterval
     */
    private $authExpire;

    /**
     *JSON web token encryption key.
     *
     * @see GoogleOAuth2Middleware::__construct()
     * @see GoogleOAuth2Middleware::getJwtKey()
     * @var string
     */
    private $jwtKey;

    /**
     * JSON web token encryption algorithme.
     *
     * @see GoogleOAuth2Middleware::setJwtAlgo()
     * @see GoogleOAuth2Middleware::getJwtAlgo()
     * @see GoogleOAuth2Middleware::DEFAULT_JWT_ALGO
     * @var string
     */
    private $jwtAlgo = self::DEFAULT_JWT_ALGO;

    /**
     * Attribute name added to the PSR-7 request object for the authentication infos.
     *
     * @see GoogleOAuth2Middleware::setRequestAttrName()
     * @see GoogleOAuth2Middleware::getRequestAttrName()
     * @see GoogleOAuth2Middleware::DEFAULT_REQUEST_ATTR_NAME
     * @var string
     */
    private $requestAttrName = self::DEFAULT_REQUEST_ATTR_NAME;

    /**
     * PSR-7 RequestHandler for unauthenticated requests.
     *
     * @see GoogleOAuth2Middleware::setUnauthenticatedRequestHandler()
     * @see GoogleOAuth2Middleware::getUnauthenticatedRequestHandler()
     * @var RequestHandlerInterface|null
     */
    private $unauthenticatedRequestHandler;

    /**
     * Google API client.
     *
     * @link https://github.com/google/google-api-php-client
     * @var \Google_Client
     */
    private $googleClient;

    /**
     * App version added to the JSON web token to limit the session to the current version of the app.
     *
     * @see GoogleOAuth2Middleware::setAppVersion()
     * @see GoogleOAuth2Middleware::getAppVersion()
     * @var string
     */
    private $appVersion;

    /**
     * GoogleOAuth2Middleware constructor.
     *
     * @param \Google_Client $googleClient
     * @param string $jwtKey
     * @param \DateInterval|null $authExpire
     */
    public function __construct(\Google_Client $googleClient, string $jwtKey, ?\DateInterval $authExpire = null)
    {
        $this->googleClient = $googleClient;
        $this->jwtKey = $jwtKey;
        $this->authExpire = $authExpire ?? \DateInterval::createFromDateString(self::DEFAULT_AUTH_EXPIRE);
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws GoogleOAuth2MiddlewareException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler):ResponseInterface
    {
        /*
         * Public requests
         */
        if ($this->isRequestPublic($request)) {
            return $handler->handle($request);
        }

        /*
         * Google auth requests
         */
        $googleRedirectUri = new Url($this->googleClient->getRedirectUri());
        if ($request->getUri()->getPath() == $googleRedirectUri->getPath()
            && isset($request->getQueryParams()["code"])) {

            $authToken = $this->processGoogleAccessCode($request);

            $response = $handler->handle(
                $request->withAttribute($this->getRequestAttrName(), $authToken)
            );
            if (!$response instanceof LogoutResponseInterface) {
                $response = $this->addAuthCookie($response, $authToken, $request);
            }

            return $response;
        }

        /*
         * Authenticated requests
         */
        if (($authToken = $this->readAuthCookie($request)) !== null) {
            $response = $handler->handle(
                $request->withAttribute($this->getRequestAttrName(), $authToken)
            );
            if ($response instanceof LogoutResponseInterface) {
                $response = $this->deleteAuthCookie($response, $request);
            }
            return $response;
        }

        /*
         * Unauthenticated requests
         */
        return $this->unauthenticatedRequestHandler
            ? $this->unauthenticatedRequestHandler->handle($request)
            : new RedirectResponse($this->googleClient->createAuthUrl());
    }

    /**
     * Processes a Google authentication code.
     *
     * @param ServerRequestInterface $request
     * @return array
     * @throws GoogleOAuth2MiddlewareException
     */
    private function processGoogleAccessCode(ServerRequestInterface $request):array
    {
        // loading the Google user infos
        $googleUserInfos = $this->getGoogleUserInfos($request);

        // building the auth token using Google user infos
        return [
            "googleId" => $googleUserInfos->getId(),
            "email" => $googleUserInfos->getEmail(),
            "verifiedEmail" => $googleUserInfos->getVerifiedEmail(),
            "gender" => $googleUserInfos->getGender(),
            "familyName" => $googleUserInfos->getFamilyName(),
            "givenName" => $googleUserInfos->getGivenName(),
            "locale" => $googleUserInfos->getLocale(),
            "picture" => $googleUserInfos->getPicture(),
            "name" => $googleUserInfos->getName(),
        ];
    }

    /**
     * Loads the user infos using Google API.
     *
     * @param ServerRequestInterface $request
     * @return \Google_Service_Oauth2_Userinfoplus
     * @throws GoogleOAuth2MiddlewareException
     */
    private function getGoogleUserInfos(ServerRequestInterface $request):\Google_Service_Oauth2_Userinfoplus
    {
        try {
            $accessToken = $this->googleClient->fetchAccessTokenWithAuthCode($request->getQueryParams()["code"]);
            if (isset($accessToken["error"])) {
                throw new GoogleOAuth2MiddlewareException(
                    sprintf("Google access token error (%s): %s",
                        $accessToken["error"], $accessToken["error_description"]),
                    $this
                );
            }
            $this->googleClient->setAccessToken($accessToken);
            return (new \Google_Service_Oauth2($this->googleClient))->userinfo->get();
        }
        catch (\Throwable $exception) {
            throw new GoogleOAuth2MiddlewareException(
                "Error while loading Google user infos",
                $this, 0, $exception
            );
        }
    }

    /**
     * Encodes a JSON web token with the current class paraemters.
     *
     * @param array $data
     * @return string
     */
    public function encodeJwt(array $data):string
    {
        return JWT::encode($data, $this->getJwtKey(), $this->getJwtAlgo());
    }

    /**
     * Decodes a JSON web token with the current class parameters. Returns NULL if the token can not
     * be decoded.
     *
     * @param string $jwt
     * @return array|null
     */
    public function decodeJwt(string $jwt):?array
    {
        try {
            if (($jwtData = JWT::decode($jwt, $this->jwtKey, [$this->jwtAlgo])) !== null) {
                return (array)$jwtData;
            }
        }
        catch (\Exception $exception) { }
        return null;
    }

    /**
     * Reads the auth cookie.
     *
     * @param ServerRequestInterface $request
     * @return array|null
     */
    protected function readAuthCookie(ServerRequestInterface $request):?array
    {
        if (isset($request->getCookieParams()[$this->getAuthCookieName()])
            && ($authToken = $this->decodeJwt($request->getCookieParams()[$this->getAuthCookieName()])) !== null
            && isset($authToken['_expireAt'], $authToken['_appVersion'])
            && ($this->getAppVersion() === null || $authToken['_appVersion'] == $this->getAppVersion())) {

            $expireAt = new \DateTime($authToken['_expireAt']);
            if ($expireAt > (new \DateTime('now'))) {
                return $authToken;
            }
        }
        return null;
    }

    /**
     * @param ResponseInterface $response
     * @param array $authToken
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    protected function addAuthCookie(ResponseInterface $response, array $authToken,
        ServerRequestInterface $request):ResponseInterface
    {
        // computing expiration time
        $expireAt = new \DateTime('now');
        $expireAt->add($this->authExpire);

        // adding headers
        $authToken['_expireAt'] = $expireAt->format(\DateTime::W3C);
        $authToken['_appVersion'] = $this->getAppVersion();

        // building the cookie
        return SetCookie::thatExpires(
            $this->getAuthCookieName(),
            $this->encodeJwt($authToken),
            $expireAt,
            $this->getAuthCookiePath() ?? '',
            $this->getAuthCookieDomain() ?? '',
            $this->getAuthCookieSecure(),
            $this->getAuthCookieHttpOnly()
        )->addToResponse($response);
    }

    /**
     * @param ResponseInterface $response
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    protected function deleteAuthCookie(ResponseInterface $response,
        ServerRequestInterface $request):ResponseInterface
    {
        return SetCookie::thatDeletesCookie(
            $this->getAuthCookieName(),
            $this->getAuthCookiePath() ?? '',
            $this->getAuthCookieDomain() ?? '',
            $this->getAuthCookieSecure(),
            $this->getAuthCookieHttpOnly()
        )->addToResponse($response);
    }

    /**
     * Verifies if a request points toward a public path.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected function isRequestPublic(ServerRequestInterface $request):bool
    {
        $publicPaths = $this->getPublicPaths();
        $requestPath = $request->getUri()->getPath();

        if (in_array($requestPath, $publicPaths)) {
            return true;
        }
        foreach ($publicPaths as $publicPath) {
            if (fnmatch($publicPath, $requestPath)) {
                return true;
            }
        }
        return false;
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
     * @param string $cookieDomain
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
     * @param bool $cookieHttpOnly
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
     * @param bool $cookieSecure
     */
    public function setAuthCookieSecure(bool $authCookieSecure):void
    {
        $this->authCookieSecure = $authCookieSecure;
    }

    /**
     * @param string $cookiePath
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
     * @param \DateInterval $authExpire
     */
    public function setAuthExpire(\DateInterval $authExpire):void
    {
        $this->authExpire = $authExpire;
    }

    /**
     * @return \DateInterval
     */
    public function getAuthExpire():\DateInterval
    {
        return $this->authExpire;
    }

    /**
     * @return string
     */
    public function getJwtKey():string
    {
        return $this->jwtKey;
    }

    /**
     * @return string
     */
    public function getRequestAttrName():string
    {
        return $this->requestAttrName;
    }

    /**
     * @param string $requestAttrName
     */
    public function setRequestAttrName(string $requestAttrName):void
    {
        $this->requestAttrName = $requestAttrName;
    }

    /**
     * @param string $path
     */
    public function addPublicPath(string $path):void
    {
        $this->publicPaths[] = $path;
    }

    /**
     * @return array
     */
    public function getPublicPaths():array
    {
        return $this->publicPaths;
    }

    /**
     * @param string $appVersion
     */
    public function setAppVersion(string $appVersion):void
    {
        $this->appVersion = $appVersion;
    }

    /**
     * @return string|null
     */
    public function getAppVersion():?string
    {
        return $this->appVersion;
    }

    /**
     * @return null|RequestHandlerInterface
     */
    public function getUnauthenticatedRequestHandler():?RequestHandlerInterface
    {
        return $this->unauthenticatedRequestHandler;
    }

    /**
     * @param RequestHandlerInterface $unauthenticatedRequestHandler
     */
    public function setUnauthenticatedRequestHandler(RequestHandlerInterface $unauthenticatedRequestHandler):void
    {
        $this->unauthenticatedRequestHandler = $unauthenticatedRequestHandler;
    }
}