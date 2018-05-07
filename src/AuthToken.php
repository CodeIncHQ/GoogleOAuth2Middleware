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
// Date:     07/05/2018
// Time:     18:31
// Project:  GoogleOauth2Middleware
//
declare(strict_types=1);
namespace CodeInc\GoogleOAuth2Middleware;

/**
 * Class AuthToken
 *
 * @package CodeInc\GoogleOAuth2Middleware
 * @author  Joan Fabrégat <joan@codeinc.fr>
 */
class AuthToken implements \IteratorAggregate, \ArrayAccess
{
    /**
     * @var array
     */
    private $authToken =[];

    /**
     * AuthToken constructor.
     *
     * @param array $authToken
     */
    public function __construct(array $authToken = [])
    {
        $this->authToken = $authToken;
    }

    /**
     * @param \Google_Service_Oauth2_Userinfoplus $googleUserInfos
     * @return AuthToken
     */
    public static function fromGoogleUserInfos(\Google_Service_Oauth2_Userinfoplus $googleUserInfos):self
    {
        return new self([
            'email' => $googleUserInfos->getEmail(),
            'verifiedEmail' => $googleUserInfos->getVerifiedEmail(),
            'gender' => $googleUserInfos->getGender(),
            'familyName' => $googleUserInfos->getFamilyName(),
            'givenName' => $googleUserInfos->getGivenName(),
            'name' => $googleUserInfos->getName(),
            'locale' => $googleUserInfos->getLocale(),
            'picture' => $googleUserInfos->getPicture(),
        ]);
    }

    /**
     * Returns the Google id.
     *
     * @return string|null
     */
    public function getGoogleId():?string
    {
        return $this->authToken['googleId'] ?? null;
    }

    /**
     * Returns the email address.
     *
     * @return null|string
     */
    public function getEmail():?string
    {
        return $this->authToken['email'] ?? null;
    }

    /**
     * Checks if the email address is verified.
     *
     * @return null|bool
     */
    public function isEmailVerified():?bool
    {
        return isset($this->authToken['verifiedEmail']) ? (bool)$this->authToken['verifiedEmail'] : null;
    }

    /**
     * Returns the gender.
     *
     * @return null|string
     */
    public function getGender():?string
    {
        return $this->authToken['gender'] ?? null;
    }

    /**
     * Returns the family name.
     *
     * @return null|string
     */
    public function getFamilyName():?string
    {
        return $this->authToken['familyName'] ?? null;
    }

    /**
     * Returns the given name.
     *
     * @return null|string
     */
    public function getGivenName():?string
    {
        return $this->authToken['givenName'] ?? null;
    }

    /**
     * Returns the name.
     *
     * @return null|string
     */
    public function getName():?string
    {
        return $this->authToken['name'] ?? null;
    }

    /**
     * Returns the locale.
     *
     * @return null|string
     */
    public function getLocale():?string
    {
        return $this->authToken['locale'] ?? null;
    }

    /**
     * Returns the picture URL.
     *
     * @return null|string
     */
    public function getPicture():?string
    {
        return $this->authToken['picture'] ?? null;
    }

    /**
     * Returns the auth token as an array.
     *
     * @return array
     */
    public function toArray():array
    {
        return $this->authToken;
    }

    /**
     * @inheritdoc
     * @return \ArrayIterator
     */
    public function getIterator():\ArrayIterator
    {
        return new \ArrayIterator($this->authToken);
    }

    /**
     * @inheritdoc
     * @param string|int $offset
     */
    public function offsetUnset($offset)
    {
        return;
    }

    /**
     * @inheritdoc
     * @param string|int $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value)
    {
        return;
    }

    /**
     * @inheritdoc
     * @param string|int $offset
     * @return mixed|null
     */
    public function offsetGet($offset)
    {
        return $this->authToken[$offset] ?? null;
    }

    /**
     * @inheritdoc
     * @param string|int $offset
     * @return bool
     */
    public function offsetExists($offset):bool
    {
        return array_key_exists($offset, $this->authToken);
    }

}