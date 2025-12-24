<?php
/**
 * Plugin Name: Images Scanner
 * Plugin URI: https://github.com/heroesoebekti/scan_images
 * Description: use for enhance SLiMS security by detecting and preventing the upload of image files (such as covers or member photos) that have been compromised with malware, specifically malicious PHP code (webshells) embedded within the metadata (EXIF) or the file structure
 * Version: 0.0.1
 * Author: Heru Subekti
 * Author URI: https://github.com/heroesoebekti/
 */

// plugin instance
$plugin = \SLiMS\Plugins::getInstance();

// registering menus
$plugin->registerMenu('system', 'Images Scanner', __DIR__ . '/index.php');