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
use CodeInc\GoogleOAuth2Middleware\Validators\PublicRequests\PublicRequestValidatorInterface;
use CodeInc\GoogleOAuth2Middleware\Responses\LogoutResponseInterface;
use CodeInc\GoogleOAuth2Middleware\Validators\Users\UserValidatorInterface;
use CodeInc\Psr7Responses\RedirectResponse;
use CodeInc\Psr7Responses\UnauthorizedResponse;
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
     * Auth expire.
     *
     * @var \DateInterval
     */
    private $authExpire;

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
    private $jwtAlgo = self::DEFAULT_JWT_ALGO;

    /**
     * Attribute name added to the PSR-7 request object for the authentication infos.
     *
     * @var string
     */
    private $requestAttrName = self::DEFAULT_REQUEST_ATTR_NAME;

    /**
     * PSR-15 RequestHandler for unauthenticated requests.
     *
     * @var RequestHandlerInterface|null
     */
    private $unauthenticatedRequestHandler;

    /**
     * PSR-15 RequestHandler for oauth callback requests.
     *
     * @var RequestHandlerInterface|null
     */
    private $oauthCallbackRequestHandler;

    /**
     * Google API client.
     *
     * @link https://github.com/google/google-api-php-client
     * @var \Google_Client
     */
    private $googleClient;

    /**
     * OAuth2 redirect URI (the one receiving the "code" parameter)
     *
     * @var string
     */
    private $oauthCallbackUri;

    /**
     * App version added to the JSON web token to limit the session to the current version of the app.
     *
     * @var string
     */
    private $appVersion;

    /**
     * User validators.
     *
     * @var UserValidatorInterface[]
     */
    private $userValidators = [];

    /**
     * Public PSR-7 requests validators.
     *
     * @var PublicRequestValidatorInterface[]
     */
    private $publicRequestValidators = [];

    /**
     * Includes the picture in the auth token.
     *
     * @var bool
     */
    public $authTokenIncludePicture = true;

    /**
     * Includes the locale in the auth token.
     *
     * @var bool
     */
    public $authTokenIncludeLocale = true;

    /**
     * Includes the gender in the auth token.
     *
     * @var bool
     */
    public $authTokenIncludeGender = true;

    /**
     * Includes the user name, given name and family name in the auth token.
     *
     * @var bool
     */
    public $authTokenIncludeName = true;

    /**
     * Includes the user email in the auth token.
     *
     * @var bool
     */
    public $authTokenIncludeEmail = true;

    /**
     * GoogleOAuth2Middleware constructor.
     *
     * @param \Google_Client $googleClient
     * @param string $jwtKey
     * @param string $oauthCallbackUri
     * @param \DateInterval|null $authExpire
     */
    public function __construct(\Google_Client $googleClient, string $jwtKey, string $oauthCallbackUri,
        ?\DateInterval $authExpire = null)
    {
        $this->googleClient = $googleClient;
        $this->googleClient->setRedirectUri($oauthCallbackUri);
        $this->jwtKey = $jwtKey;
        $this->oauthCallbackUri = $oauthCallbackUri;
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
        // Public requests
        if ($response = $this->processPublicRequests($request, $handler)) {
            return $response;
        }

        // Google oauth requests
        if ($response = $this->processGoogleOauthRequests($request, $handler)) {
            return $response;
        }

        // Authenticated requests
        if ($response = $this->processAuthenticatedRequests($request, $handler)) {
            return $response;
        }

        // Unauthenticated requests
        return $this->processUnauthenticatedRequests($request);
    }

    /**
     * Processes the public requests. Returns the respnse or null if the request is not public.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return null|ResponseInterface
     */
    private function processPublicRequests(ServerRequestInterface $request,
        RequestHandlerInterface $handler):?ResponseInterface
    {
        if ($this->isRequestPublic($request)) {
            return $handler->handle($request);
        }
        return null;
    }

    /**
     * Processes the Google OAuth requests. Returns the response if the request is a Google OAuth
     * request including an authentication code or null of other requests.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return null|ResponseInterface
     * @throws GoogleOAuth2MiddlewareException
     */
    private function processGoogleOauthRequests(ServerRequestInterface $request,
        RequestHandlerInterface $handler):?ResponseInterface
    {
        // checking the request
        $oauthCallbackUri = new Url($this->oauthCallbackUri);
        if ($request->getUri()->getPath() == $oauthCallbackUri->getPath()
            && isset($request->getQueryParams()["code"])) {

            // loading the Google user infos
            $googleUserInfos = $this->getGoogleUserInfos($request);

            // validating the user
            if (!$this->validateUser($googleUserInfos)) {
                return new UnauthorizedResponse();
            }

            // building the auth token
            $authToken = $this->buildAuthToken($googleUserInfos);

            // if a specific handler is given for the OAuth callback requests
            if ($this->oauthCallbackRequestHandler) {
                $handler = $this->oauthCallbackRequestHandler;
            }

            // processing the PSR-7 request with the auth token
            $response = $handler->handle(
                $request->withAttribute($this->requestAttrName, $authToken)
            );

            // adding the auth cookie to the PSR-7 response
            if (!$response instanceof LogoutResponseInterface) {
                $response = $this->getAuthCookie($authToken)->addToResponse($response);
            }

            return $response;
        }
        return null;
    }

    /**
     * Proesses the authenticated requrests. Returns null if the request does not include the authentication cookie.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return null|ResponseInterface
     */
    private function processAuthenticatedRequests(ServerRequestInterface $request,
        RequestHandlerInterface $handler):?ResponseInterface
    {
        if (($authTokenData = $this->readAuthCookie($request)) !== null) {
            $response = $handler->handle(
                $request->withAttribute($this->getRequestAttrName(), new AuthToken($authTokenData))
            );
            if ($response instanceof LogoutResponseInterface) {
                $response = $this->getAuthDeleteCookie()->addToResponse($response);
            }
            return $response;
        }
        return null;
    }

    /**
     * Processes the unauthenticated requests.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    private function processUnauthenticatedRequests(ServerRequestInterface $request):ResponseInterface
    {
        return $this->unauthenticatedRequestHandler
            ? $this->unauthenticatedRequestHandler->handle($request)
            : new RedirectResponse($this->googleClient->createAuthUrl());
    }

    /**
     * Validates a user using the supplied validators.
     *
     * @param \Google_Service_Oauth2_Userinfoplus $googleUserInfos
     * @return bool
     */
    private function validateUser(\Google_Service_Oauth2_Userinfoplus $googleUserInfos):bool
    {
        if (!empty($this->userValidators)) {
            foreach ($this->userValidators as $validator) {
                if ($validator->validateUser($googleUserInfos)) {
                    return true;
                }
            }
            return false;
        }
        else {
            return true;
        }
    }

    /**
     * Builds the auth token using the user infos fetched via the Google API.
     *
     * @param \Google_Service_Oauth2_Userinfoplus $googleUserInfos
     * @return AuthToken
     */
    private function buildAuthToken(\Google_Service_Oauth2_Userinfoplus $googleUserInfos):AuthToken
    {
        $authTokenData = ['googleId' => $googleUserInfos->getId()];

        if ($this->authTokenIncludeEmail) {
            $authTokenData['email'] = $googleUserInfos->getEmail();
            $authTokenData['verifiedEmail'] = $googleUserInfos->getVerifiedEmail();
        }
        if ($this->authTokenIncludeGender) {
            $authTokenData['gender'] = $googleUserInfos->getGender();
        }
        if ($this->authTokenIncludeName) {
            $authTokenData['familyName'] = $googleUserInfos->getFamilyName();
            $authTokenData['givenName'] = $googleUserInfos->getGivenName();
            $authTokenData['name'] = $googleUserInfos->getName();
        }
        if ($this->authTokenIncludeLocale) {
            $authTokenData['locale'] = $googleUserInfos->getLocale();
        }
        if ($this->authTokenIncludePicture) {
            $authTokenData['picture'] = $googleUserInfos->getPicture();
        }

        return new AuthToken($authTokenData);
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
            $accessToken = $this->googleClient->fetchAccessTokenWithAuthCode($request->getQueryParams()['code']);
            if (isset($accessToken['error'])) {
                throw new GoogleOAuth2MiddlewareException(
                    sprintf('Google access token error (%s): %s',
                        $accessToken['error'], $accessToken['error_description']),
                    $this
                );
            }
            $this->googleClient->setAccessToken($accessToken);
            return (new \Google_Service_Oauth2($this->googleClient))->userinfo->get();
        }
        catch (\Throwable $exception) {
            throw new GoogleOAuth2MiddlewareException(
                'Error while loading Google user infos',
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
        return JWT::encode($data, $this->jwtKey, $this->jwtAlgo);
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
        if (isset($request->getCookieParams()[$this->authCookieName])
            && ($authToken = $this->decodeJwt($request->getCookieParams()[$this->authCookieName])) !== null
            && isset($authToken['_expireAt'], $authToken['_appVersion'])
            && ($this->appVersion === null || $authToken['_appVersion'] == $this->appVersion)) {

            $expireAt = new \DateTime($authToken['_expireAt']);
            if ($expireAt > (new \DateTime('now'))) {
                return $authToken;
            }
        }
        return null;
    }

    /**
     * @param AuthToken $authToken
     * @return SetCookie
     */
    protected function getAuthCookie(AuthToken $authToken):SetCookie
    {
        // computing expiration time
        $expireAt = new \DateTime('now');
        $expireAt->add($this->authExpire);

        // adding headers
        $authToken['_expireAt'] = $expireAt->format(\DateTime::W3C);
        $authToken['_appVersion'] = $this->getAppVersion();

        // building the cookie
        return SetCookie::thatExpires(
            $this->authCookieName,
            $this->encodeJwt($authToken->toArray()),
            $expireAt,
            $this->authCookiePath ?? '',
            $this->authCookieDomain ?? '',
            $this->authCookieSecure,
            $this->authCookieHttpOnly
        );
    }

    /**
     * @return SetCookie
     */
    protected function getAuthDeleteCookie():SetCookie
    {
        return SetCookie::thatDeletesCookie(
            $this->authCookieName,
            $this->authCookiePath ?? '',
            $this->authCookieDomain ?? '',
            $this->authCookieSecure,
            $this->authCookieHttpOnly
        );
    }

    /**
     * Verifies if a request points toward a public path.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected function isRequestPublic(ServerRequestInterface $request):bool
    {
        foreach ($this->publicRequestValidators as $publicRequestValidator) {
            if ($publicRequestValidator->isRequestPublic($request)) {
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

    /**
     * @return null|RequestHandlerInterface
     */
    public function getOauthCallbackRequestHandler():?RequestHandlerInterface
    {
        return $this->oauthCallbackRequestHandler;
    }

    /**
     * @param RequestHandlerInterface $oauthCallbackRequestHandler
     */
    public function setOauthCallbackRequestHandler(RequestHandlerInterface $oauthCallbackRequestHandler):void
    {
        $this->oauthCallbackRequestHandler = $oauthCallbackRequestHandler;
    }

    /**
     * @param UserValidatorInterface $userValidator
     */
    public function addUserValidator(UserValidatorInterface $userValidator):void
    {
        $this->userValidators[] = $userValidator;
    }

    /**
     * @return UserValidatorInterface[]
     */
    public function getUserValidators():array
    {
        return $this->userValidators;
    }

    /**
     * @param PublicRequestValidatorInterface $publicRequestValidator
     */
    public function addPublicRequestValidator(PublicRequestValidatorInterface $publicRequestValidator):void
    {
        $this->publicRequestValidators[] = $publicRequestValidator;
    }

    /**
     * @return PublicRequestValidatorInterface[]
     */
    public function getPublicRequestValidators():array
    {
        return $this->publicRequestValidators;
    }

    /**
     * @return string
     */
    public function getOauthCallbackUri():string
    {
        return $this->oauthCallbackUri;
    }

    /**
     * Includes all the data in the auth token :
     * - email
     * - gender
     * - locale
     * - given name, family name and name
     * - picture
     */
    public function setAuthTokenIncludeAll():void
    {
        $this->authTokenIncludeEmail = true;
        $this->authTokenIncludeGender = true;
        $this->authTokenIncludeLocale = true;
        $this->authTokenIncludeName = true;
        $this->authTokenIncludePicture = true;
    }

    /**
     * Includes non data in the auth token.
     */
    public function setAuthTokenIncludeNone():void
    {
        $this->authTokenIncludeEmail = false;
        $this->authTokenIncludeGender = false;
        $this->authTokenIncludeLocale = false;
        $this->authTokenIncludeName = false;
        $this->authTokenIncludePicture = false;
    }
}