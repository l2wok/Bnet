<?php
namespace App\Helpers\Bnet\GrantType;

class ClientCredentials implements IGrantType
{
    const GRANT_TYPE = 'client_credentials';

    public function validateParameters(&$parameters)
    {
    }
}
