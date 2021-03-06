<?php
/**
 * Opauth Multi-provider authentication framework for PHP package for FuelPHP Framework
 *
 * @package    Fuel-Opauth
 * @version    1.0
 * @author     Andreo Vieira <andreoav@gmail.com>
 * @license    MIT License
 * @copyright  2012 Andreo Vieira
 * @link       http://www.inf.ufsm.br/~andreoav
 */

Autoloader::add_core_namespace('Opauth');

Autoloader::add_classes(array(
    'Opauth\\Opauth'           => __DIR__ . '/classes/Opauth.php',
    'Opauth\\OpauthStrategy'   => __DIR__ . '/classes/OpauthStrategy.php',
    'Opauth\\FacebookStrategy' => __DIR__ . '/classes/Strategy/FacebookStrategy.php',
    'Opauth\\TwitterStrategy'  => __DIR__ . '/classes/Strategy/TwitterStrategy.php',
    'Opauth\\GoogleStrategy'   => __DIR__ . '/classes/Strategy/GoogleStrategy.php',
    'Opauth\\YahoojpStrategy'  => __DIR__ . '/classes/Strategy/YahoojpStrategy.php',
    'Opauth\\HttpClient'       => __DIR__ . '/classes/Strategy/YahoojpStrategy.php',
    'Opauth\\InstagramStrategy'=> __DIR__ . '/classes/Strategy/InstagramStrategy.php',
    'Opauth\\FreeeStrategy'     => __DIR__ . '/classes/Strategy/FreeeStrategy.php',
));