<?php
namespace App\Helpers\Bnet\GrantType;

use App\Helpers\Bnet\InvalidArgumentException;

class AuthorizationCode implements IGrantType
{
    const GRANT_TYPE = 'authorization_code';

    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['code']))
        {
            throw new InvalidArgumentException(
                'The \'code\' parameter must be defined for the Authorization Code grant type',
                InvalidArgumentException::MISSING_PARAMETER
            );
        }
        elseif (!isset($parameters['redirect_uri']))
        {
            throw new InvalidArgumentException(
                'The \'redirect_uri\' parameter must be defined for the Authorization Code grant type',
                InvalidArgumentException::MISSING_PARAMETER
            );
        }
    }
}
