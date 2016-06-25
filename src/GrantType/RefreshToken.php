<?php
namespace GrantType;

use InvalidArgumentException;

class RefreshToken implements IGrantType
{
    const GRANT_TYPE = 'refresh_token';

    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['refresh_token']))
        {
            throw new InvalidArgumentException(
                'The \'refresh_token\' parameter must be defined for the refresh token grant type',
                InvalidArgumentException::MISSING_PARAMETER
            );
        }
    }
}
