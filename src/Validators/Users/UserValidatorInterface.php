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
// Time:     17:35
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware\Validators\Users;

/**
 * Interface UserValidatorInterface
 *
 * @package CodeInc\GoogleOAuth2Middleware\Validators\Users
 * @author Joan Fabrégat <joan@codeinc.fr>
 */
interface UserValidatorInterface
{
    /**
     * Validates the authentification of the user.
     *
     * @param \Google_Service_Oauth2_Userinfoplus $userInfos
     * @return bool
     */
    public function validateUser(\Google_Service_Oauth2_Userinfoplus $userInfos):bool;
}