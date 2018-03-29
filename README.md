# Google OAuth 2 Middleware

`GoogleOAuth2Middleware` is a [PSR-15](https://www.php-fig.org/psr/psr-15/) middleware written in PHP 7 intended to manage Google OAuth2 authentication using JSON web tokens. The web tokens are generated and read by the [firebase/php-jwt](https://github.com/firebase/php-jwt) library.

The authentication informations are stored in a JSON web token save in a cookie called `__auth` (by default). 

Once the user is authenticated, either when receiving an auth code from Google or using the auth cookie, the user informations are made available in an attribute of the [PSR-7](https://www.php-fig.org/psr/psr-7/) request the called `auth` (by default).

You can disconnect the current user by sending a PSR-7 response implementing [`LogoutResponseInterface`](src/Responses/LogoutResponseInterface.php).


## Usage

```php
<?php
use CodeInc\GoogleOAuth2Middleware\GoogleOAuth2Middleware;

$googleOAuth2Middleware = new GoogleOAuth2Middleware(
    // a fully configures Google client (the client redirect URI must be set)
    new Google_Client(), 
    
    // the JWT encryption key
    "a_very_secret_key", 
    
    // the lifespan of the authentication (optionnal, 30 minutres by default)
    DateInterval::createFromDateString("1 hour") 
);

// You can (optionnally) specify a request handler which will be called for unauthenticated requests.
// If not request handler is set the middleware will generate a PSR-7 redirect response toward the
// Google Oauth 2 page
$googleOAuth2Middleware->setUnauthenticatedRequestHandler(new APSR7RequestHandler());
```


## Installation

This library is available through [Packagist](https://packagist.org/packages/codeinc/google-oauth2-middleware) and can be installed using [Composer](https://getcomposer.org/): 

```bash
composer require codeinc/google-oauth2-middleware
```


## License 
This library is published under the MIT license (see the [`LICENSE`](LICENSE) file).

