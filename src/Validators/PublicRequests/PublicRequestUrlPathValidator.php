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
// Date:     13/04/2018
// Time:     18:10
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\Validators\PublicRequests;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class PublicRequestUrlPathValidator
 *
 * @package CodeInc\GoogleOAuth2Middleware\Validators\PublicRequests
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class PublicRequestUrlPathValidator implements PublicRequestValidatorInterface
{
    /**
     * @var string[]
     */
    private $publicPaths = [];

    /**
     * UrlPathValidator constructor.
     *
     * @param string|string[]|null $paths
     */
    public function __construct($paths = null)
    {
        if (is_array($paths)) {
            foreach ($paths as $path) {
                $this->addPublicPath($path);
            }
        }
        elseif (is_string($paths)) {
            $this->addPublicPath($paths);
        }
    }

    /**
     * Adds a public URL path.
     *
     * @param string $publicPath
     */
    public function addPublicPath(string $publicPath):void
    {
        if (!in_array($publicPath, $this->publicPaths)) {
            $this->publicPaths[] = $publicPath;
        }
    }

    /**
     * Returns the list of public URL paths.
     *
     * @return string[]
     */
    public function getPublicPaths():array
    {
        return $this->publicPaths;
    }

    /**
     * @inheritdoc
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function isRequestPublic(ServerRequestInterface $request):bool
    {
        $uriPath = $request->getUri()->getPath();

        // if the request path is in the public paths array
        if (in_array($uriPath, $this->publicPaths)) {
            return true;
        }

        // if the request path matches a public shell pattern
        foreach ($this->publicPaths as $publicPath) {
            if (fnmatch($publicPath, $uriPath)) {
                return true;
            }
        }

        return false;
    }

}