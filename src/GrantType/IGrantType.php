<?php
namespace GrantType;

interface IGrantType 
{
    public function validateParameters(&$parameters);
}
