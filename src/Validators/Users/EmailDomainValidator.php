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
// Time:     17:37
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\Validators\Users;

/**
 * Class EmailDomainValidator
 *
 * @package CodeInc\GoogleOAuth2Middleware\Validators\Users
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class EmailDomainValidator implements UserValidatorInterface
{
    /**
     * @var string[]
     */
    private $allowedDomains = [];

    /**
     * DomainValidator constructor.
     *
     * @param string|string[]|null $allowedDomains
     */
    public function __construct($allowedDomains = null)
    {
        if (is_array($allowedDomains)) {
            foreach ($allowedDomains as $allowedDomain) {
                $this->addAllowedDomain($allowedDomain);
            }
        }
        elseif (is_string($allowedDomains)) {
            $this->addAllowedDomain($allowedDomains);
        }
    }

    /**
     * Adds an allowed domain.
     *
     * @param string $allowedDomain
     */
    public function addAllowedDomain(string $allowedDomain):void
    {
        $allowedDomain = strtolower($allowedDomain);
        if (!in_array($allowedDomain, $this->allowedDomains)) {
            $this->allowedDomains[] = $allowedDomain;
        }
    }

    /**
     * Returns all the allowed domains.
     *
     * @return string[]
     */
    public function getAllowedDomains():array
    {
        return $this->allowedDomains;
    }

    /**
     * @inheritdoc
     * @param \Google_Service_Oauth2_Userinfoplus $userInfos
     * @return bool
     */
    public function validateUser(\Google_Service_Oauth2_Userinfoplus $userInfos):bool
    {
        return $userInfos->getVerifiedEmail()
            && preg_match('/@(.+)$/u', $userInfos->getEmail(), $matches)
            && in_array(strtolower($matches[1]), $this->allowedDomains);
    }
}