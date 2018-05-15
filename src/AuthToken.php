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
class AuthToken implements \IteratorAggregate
{
    /**
     * @var int
     */
    private $googleId;

    /**
     * @var string|null
     */
    private $email;

    /**
     * @var bool
     */
    private $verifiedEmail = false;

    /**
     * @var string|null
     */
    private $gender;

    /**
     * @var string|null
     */
    private $familyName;

    /**
     * @var string|null
     */
    private $givenName;

    /**
     * @var string|null
     */
    private $name;

    /**
     * @var string|null
     */
    private $locale;

    /**
     * @var string|null
     */
    private $picture;

    /**
     * @var string
     */
    private $expiresAt;

    /**
     * @var string|null
     */
    private $appVersion;

    /**
     * AuthToken constructor.
     *
     * @param int         $googleId
     * @param null|string $appVersion
     */
    public function __construct(int $googleId, ?string $appVersion = null)
    {
        $this->googleId = $googleId;
        $this->setExpiresAt((new \DateTime('now'))
            ->add(\DateInterval::createFromDateString('30 min')));
        $this->appVersion = $appVersion;
    }

    /**
     * Transforms the auth token into an array.
     *
     * @throws \ReflectionException
     * @return array
     */
    public function toArray():array
    {
        $array = [];
        foreach (array_keys((new \ReflectionClass($this))->getDefaultProperties()) as $property) {
            $array[$property] = $this->{$property};
        }
        return $array;
    }

    /**
     * Creates an auth token using an array;
     *
     * @param array $array
     * @return AuthToken
     * @throws AuthTokenException
     * @throws \ReflectionException
     */
    public static function fromArray(array $array):AuthToken
    {
        if (!isset($array['googleId'])) {
            throw new AuthTokenException('The \'googleId\' key is missing in the array');
        }
        if (!is_numeric($array['googleId'])) {
            throw new AuthTokenException(sprintf('The Google ID \'%s\' is invalid', $array['googleId']));
        }
        $authToken =new AuthToken((int)$array['googleId']);
        foreach (array_keys((new \ReflectionClass($authToken))->getDefaultProperties()) as $property) {
            if (array_key_exists($property, $array)) {
                $authToken->{$property} = $array[$property];
            }
        }
        return $authToken;
    }

    /**
     * @return int
     */
    public function getGoogleId():int
    {
        return $this->googleId;
    }

    /**
     * @return null|string
     */
    public function getEmail():?string
    {
        return $this->email;
    }

    /**
     * @param null|string $email
     */
    public function setEmail(?string $email):void
    {
        $this->email = $email;
    }

    /**
     * @return bool
     */
    public function isVerifiedEmail():bool
    {
        return $this->verifiedEmail;
    }

    /**
     * @param bool $verifiedEmail
     */
    public function setVerifiedEmail(bool $verifiedEmail):void
    {
        $this->verifiedEmail = $verifiedEmail;
    }

    /**
     * @return null|string
     */
    public function getGender():?string
    {
        return $this->gender;
    }

    /**
     * @param null|string $gender
     */
    public function setGender(?string $gender):void
    {
        $this->gender = $gender;
    }

    /**
     * @return null|string
     */
    public function getFamilyName():?string
    {
        return $this->familyName;
    }

    /**
     * @param null|string $familyName
     */
    public function setFamilyName(?string $familyName):void
    {
        $this->familyName = $familyName;
    }

    /**
     * @return null|string
     */
    public function getGivenName():?string
    {
        return $this->givenName;
    }

    /**
     * @param null|string $givenName
     */
    public function setGivenName(?string $givenName):void
    {
        $this->givenName = $givenName;
    }

    /**
     * @return null|string
     */
    public function getName():?string
    {
        return $this->name;
    }

    /**
     * @param null|string $name
     */
    public function setName(?string $name):void
    {
        $this->name = $name;
    }

    /**
     * @return null|string
     */
    public function getLocale():?string
    {
        return $this->locale;
    }

    /**
     * @param null|string $locale
     */
    public function setLocale(?string $locale):void
    {
        $this->locale = $locale;
    }

    /**
     * @return null|string
     */
    public function getPicture():?string
    {
        return $this->picture;
    }

    /**
     * @param null|string $picture
     */
    public function setPicture(?string $picture):void
    {
        $this->picture = $picture;
    }

    /**
     * @return \DateTime
     */
    public function getExpiresAt():\DateTime
    {
        return new \DateTime($this->expiresAt);
    }

    /**
     * @param \DateTime $expiresAt
     */
    public function setExpiresAt(\DateTime $expiresAt):void
    {
        $this->expiresAt = $expiresAt->format(\DateTime::ATOM);
    }

    /**
     * Verifies if the auth token is expired.
     *
     * @return bool
     */
    public function isExpired():bool
    {
        return $this->getExpiresAt() <= (new \DateTime('now'));
    }

    /**
     * @return null|string
     */
    public function getAppVersion():?string
    {
        return $this->appVersion;
    }

    /**
     * @param null|string $appVersion
     */
    public function setAppVersion(?string $appVersion):void
    {
        $this->appVersion = $appVersion;
    }

    /**
     * Validates the auth token version.
     *
     * @param string $appVersion
     * @return bool
     */
    public function isOfVersion(string $appVersion):bool
    {
        return version_compare($appVersion, $this->appVersion, '==');
    }

    /**
     * @param null|string $appVersion
     * @return bool
     */
    public function isValid(?string $appVersion = null):bool
    {
        return (($appVersion === null || $this->isOfVersion($appVersion)) && !$this->isExpired());
    }

    /**
     * @inheritdoc
     * @return \ArrayIterator
     * @throws \ReflectionException
     */
    public function getIterator():\ArrayIterator
    {
        return new \ArrayIterator($this->toArray());
    }
}