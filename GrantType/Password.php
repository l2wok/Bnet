<?php
namespace Bnet\GrantType;

use Bnet\InvalidArgumentException;

class Password implements IGrantType
{
    const GRANT_TYPE = 'password';

    public function validateParameters(&$parameters)
    {
        if (!isset($parameters['username']))
        {
            throw new InvalidArgumentException(
                'The \'username\' parameter must be defined for the Password grant type',
                InvalidArgumentException::MISSING_PARAMETER
            );
        }
        elseif (!isset($parameters['password']))
        {
            throw new InvalidArgumentException(
                'The \'password\' parameter must be defined for the Password grant type',
                InvalidArgumentException::MISSING_PARAMETER
            );
        }
    }
}
