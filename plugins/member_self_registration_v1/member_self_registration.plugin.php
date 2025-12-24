<?php
/**
 * Plugin Name: member_self_registration
 * Plugin URI: https://github.com/drajathasan/member_self_registration
 * Description: Plugin untuk daftar online V1
 * Version: 1.0.0 V.1
 * Author: Drajat Hasan Makmur A
 * Author URI: Drajat Hasan
 */

// get plugin instance
$plugin = \SLiMS\Plugins::getInstance();

// registering menus
$plugin->registerMenu('membership', 'Daftar Online', __DIR__ . '/index.php');
$plugin->registerMenu('opac', 'Daftar Online', __DIR__ . '/daftar_online.inc.php');
