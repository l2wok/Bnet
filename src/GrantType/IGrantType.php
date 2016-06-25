<?php
namespace Bnet\GrantType;

interface IGrantType 
{
    public function validateParameters(&$parameters);
}
