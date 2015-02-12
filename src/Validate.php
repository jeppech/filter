<?php

namespace Jeppech\Filter;

class Validate
{
    /**
     * Validates $value as email
     *
     * @param string $value
     * @return string|bool
     */
    public static function email($value)
    {
        $options = array(
            "options" => array(
                "default" => false
            )
        );

        return filter_var($value, FILTER_VALIDATE_EMAIL);
    }

    /**
     * Validates $value as integer, optionally within the given range.
     *
     * @param int $value
     * @param int $min_range
     * @param int $max_range
     * @param bool $allow_hex
     * @param bool $allow_oct
     * @return string|bool
     */
    public static function int($value, $min = 0, $max = false, $allow_hex = false, $allow_oct = false)
    {
        $options = array(
            "options" => array(
                "default"   => false,
                "min_range" => $min,
                "max_range" => ($max === false ? PHP_INT_MAX : $max)
            ),
            "flags" =>  ($allow_hex ? FILTER_FLAG_ALLOW_HEX : false) |
                        ($allow_oct ? FILTER_FLAG_ALLOW_OCTAL : false)
        );

        return filter_var($value, FILTER_VALIDATE_INT, $options);
    }

    /**
     * Validates $value as IPv4/IPv6
     *
     * @param string $value
     * @param bool $only_v4
     * @param bool $only_v6
     * @param bool $no_private
     * @param bool $no_reserved
     * @return string|bool
     */
    public static function ip($value, $only_v4 = false, $only_v6 = false, $no_private = false, $no_reserved = false)
    {
        $options = array(
            "options" => array(
                "default" => false
            ),
            "flags" =>  ($only_v4 ? FILTER_FLAG_IPV4 : false) |
                        ($only_v6 ? FILTER_FLAG_IPV6 : false) |
                        ($no_private ? FILTER_FLAG_NO_PRIV_RANGE : false) |
                        ($no_reserved ? FILTER_FLAG_NO_RES_RANGE : false)
        );

        return filter_var($value, FILTER_VALIDATE_IP, $options);
    }

    /**
     * Validates $value as URL, according to http://www.faqs.org/rfcs/rfc2396.html
     *
     * @param string $value
     * @param bool $require_path
     * @param bool $require_query
     * @return string|bool
     */
    public static function url($value, $require_path = false, $require_query = false)
    {
        $options = array(
            "options" => array(
                "default" => false
            ),
            "flags" =>  ($require_path ? FILTER_FLAG_PATH_REQUIRED : false) |
                        ($require_query ? FILTER_FLAG_QUERY_REQUIRED : false)
        );

        return filter_var($value, FILTER_VALIDATE_URL, $options);
    }

    /**
     * Validates $value as boolean
     *
     * @param bool $value
     * @param bool $null_on_fail
     * @return string|bool
     */
    public static function bool($value, $null_on_fail = false)
    {
        $options = array(
            "options" => array(
                "default" => false
            ),
            "flags" => ($null_on_fail ? FILTER_NULL_ON_FAILURE : false)
        );

        return filter_var($value, FILTER_VALIDATE_bool, $options);
    }

    /**
     * Validates $value as float
     *
     * @param float $value
     * @param string $decimal
     * @param bool $allow_thousand_point
     * @return string|bool
     */
    public static function float($value, $decimal = ".", $allow_thousand_point = false)
    {
        $options = array(
            "options" => array(
                "default" => false,
                "decimal" => $decimal
            ),
            "flags" => ($allow_thousand_point ? FILTER_FLAG_ALLOW_THOUSAND : false)
        );

        return filter_var($value, FILTER_VALIDATE_FLOAT, $options);
    }

    /**
     * Valudate $value against a regular expression
     * @param mixed $value
     * @param string $regex
     * @return string|bool
     */
    public static function regex($value, $regex)
    {
        $options = array(
            "options" => array(
                "default" => false,
                "regex" => $regex
            )
        );

        return filter_var($value, FILTER_VALIDATE_REGEXP, $options);
    }
}
