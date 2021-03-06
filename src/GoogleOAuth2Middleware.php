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
use CodeInc\GoogleOAuth2Middleware\AuthTokenStorage\AuthTokenStorageDriverInterface;
use CodeInc\GoogleOAuth2Middleware\Validators\PublicRequests\PublicRequestValidatorInterface;
use CodeInc\GoogleOAuth2Middleware\Responses\LogoutResponseInterface;
use CodeInc\GoogleOAuth2Middleware\Validators\Users\UserValidatorInterface;
use CodeInc\Psr7Responses\RedirectResponse;
use CodeInc\Psr7Responses\UnauthorizedResponse;
use CodeInc\Url\Url;
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
    // other default settings
    const DEFAULT_AUTH_EXPIRE = '30 minutes';
    const DEFAULT_REQUEST_ATTR_NAME = 'auth';

    /**
     * Auth expire.
     *
     * @var \DateInterval
     */
    private $authExpire;

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
     * @var AuthTokenStorageDriverInterface
     */
    private $authTokenStorageDriver;

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
     * @param AuthTokenStorageDriverInterface $authTokenStorageDriver
     * @param string $oauthCallbackUri
     * @param \DateInterval|null $authExpire
     */
    public function __construct(\Google_Client $googleClient, AuthTokenStorageDriverInterface $authTokenStorageDriver,
        string $oauthCallbackUri, ?\DateInterval $authExpire = null)
    {
        $this->googleClient = $googleClient;
        $this->googleClient->setRedirectUri($oauthCallbackUri);
        $this->authTokenStorageDriver = $authTokenStorageDriver;
        $this->oauthCallbackUri = $oauthCallbackUri;
        $this->authExpire = $authExpire ?? \DateInterval::createFromDateString(self::DEFAULT_AUTH_EXPIRE);
    }

    /**
     * @inheritdoc
     * @param ServerRequestInterface  $request
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
     * @param ServerRequestInterface  $request
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
            return $this->attachAuthTokenToResponse(
                $handler->handle(
                    $request->withAttribute($this->requestAttrName, $authToken)
                ),
                $authToken
            );
        }
        return null;
    }

    /**
     * Attaches the auth token to a response. The auth token is not attached to responses implementing the
     * LogoutResponseInterface interface.
     *
     * @param ResponseInterface $response
     * @param AuthToken         $authToken
     * @return ResponseInterface
     */
    private function attachAuthTokenToResponse(ResponseInterface $response, AuthToken $authToken):ResponseInterface
    {
        // updates the auth token
        if (!$response instanceof LogoutResponseInterface) {
            $authToken = clone $authToken;
            $authToken->updateExpiresAt($this->authExpire);
            return $this->authTokenStorageDriver->saveAuthToken($authToken, $response);
        }

        // deletes the auth token
        else {
            return $this->authTokenStorageDriver->deleteAuthToken($response);
        }
    }

    /**
     * Processes the authenticated requrests. Returns null if the request does not include the authentication cookie.
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return null|ResponseInterface
     */
    private function processAuthenticatedRequests(ServerRequestInterface $request,
        RequestHandlerInterface $handler):?ResponseInterface
    {
        // if the auth token exists among the cookies
        $authToken = $this->authTokenStorageDriver->getAuthToken($request);
        if ($authToken)
        {
            // if the token is not expired and is valid for the current version
            if ($authToken->isValid($this->appVersion)) {

                // processing the request
                return $this->attachAuthTokenToResponse(
                    $handler->handle(
                        $request->withAttribute($this->getRequestAttrName(), $authToken)
                    ),
                    $authToken
                );
            }
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
        $authToken = new AuthToken((int)$googleUserInfos->getId(), $this->getAppVersion(), $this->authExpire);

        if ($this->authTokenIncludeEmail) {
            $authToken->setEmail($googleUserInfos->getEmail());
            $authToken->setVerifiedEmail($googleUserInfos->getVerifiedEmail());
        }
        if ($this->authTokenIncludeGender) {
            $authToken->setGender($googleUserInfos->getGender());
        }
        if ($this->authTokenIncludeName) {
            $authToken->setFamilyName($googleUserInfos->getFamilyName());
            $authToken->setGivenName($googleUserInfos->getGivenName());
            $authToken->setName($googleUserInfos->getName());
        }
        if ($this->authTokenIncludeLocale) {
            $authToken->setLocale($googleUserInfos->getLocale());
        }
        if ($this->authTokenIncludePicture) {
            $authToken->setPicture($googleUserInfos->getPicture());
        }

        return $authToken;
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
     * @param \DateInterval $authExpire
     */
    public function setAuthExpire(\DateInterval $authExpire):void
    {
        $this->authExpire = $authExpire;
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
     * @return \DateInterval
     */
    public function getAuthExpire():\DateInterval
    {
        return $this->authExpire;
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