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
// Time:     17:42
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\UserValidators;

/**
 * Class EmailsValidator
 *
 * @package CodeInc\GoogleOAuth2Middleware\UserValidators
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
class EmailAddressesValidator implements UserValidatorInterface
{
    /**
     * @var string[]
     */
    private $allowedAddresses = [];

    /**
     * EmailAddressesValidator constructor.
     *
     * @param string|string[]|null $allowedAddresses
     */
    public function __construct($allowedAddresses)
    {
        if (is_array($allowedAddresses)) {
            foreach ($allowedAddresses as $allowedAddress) {
                $this->addAllowedAddress($allowedAddress);
            }
        }
        elseif (is_string($allowedAddresses)) {
            $this->addAllowedAddress($allowedAddresses);
        }
    }

    /**
     * Adds an allowed email address.
     *
     * @param string $allowedAddress
     */
    public function addAllowedAddress(string $allowedAddress):void
    {
        $allowedAddress = strtolower($allowedAddress);
        if (!in_array($allowedAddress, $this->allowedAddresses)) {
            $this->allowedAddresses[] = $allowedAddress;
        }
    }

    /**
     * Returns the allowed addresses.
     *
     * @return string[]
     */
    public function getAllowedAddresses():array
    {
        return $this->allowedAddresses;
    }

    /**
     * @inheritdoc
     * @param \Google_Service_Oauth2_Userinfoplus $userInfos
     * @return bool
     */
    public function validateUser(\Google_Service_Oauth2_Userinfoplus $userInfos):bool
    {
        return $userInfos->getVerifiedEmail() && in_array(strtolower($userInfos->getEmail()), $this->allowedAddresses);
    }
}