<?php
namespace App\Helpers\Bnet\GrantType;

interface IGrantType 
{
    public function validateParameters(&$parameters);
}
