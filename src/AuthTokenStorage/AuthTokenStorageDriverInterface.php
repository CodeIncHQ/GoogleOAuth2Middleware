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
// Time:     11:25
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\AuthTokenStorage;
use CodeInc\GoogleOAuth2Middleware\AuthToken;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Interface AuthTokenStorageInterface
 *
 * @package CodeInc\GoogleOAuth2Middleware
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
interface AuthTokenStorageDriverInterface
{
    /**
     * Saves the auth token.
     *
     * @param AuthToken $token
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function saveAuthToken(AuthToken $token, ResponseInterface $response):ResponseInterface;

    /**
     * Deletes the current auth token.
     *
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function deleteAuthToken(ResponseInterface $response):ResponseInterface;

    /**
     * Reads the auth token form a request.
     *
     * @param ServerRequestInterface $request
     * @return AuthToken|null
     */
    public function getAuthToken(ServerRequestInterface $request):?AuthToken;
}