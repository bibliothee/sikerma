<?php
/*
* @author Heru Subekti <https://github.com/heroesoebekti/>
* @copyright 2025 Heru Subekti
* @license GPL-3.0-or-later
* @File name      : scanner_config.php
*/
defined('INDEX_AUTH') OR die('Direct access not allowed!');

$config['available_dirs'] = [
    'files/' => 'Uploaded Files (Cache, Backup, Membercards, Reports, etc.)',
    'images/' => 'Default SLiMS Images (Covers, Member Photos, Assets, etc.)',
    'repository/' => 'Repository (If used)' 
];

$config['log_file_relative'] = 'suspicious_scan_log.txt';
$config['cache_list_relative'] = 'suspicious_files_list.tmp'; 
$config['realtime_log_relative'] = 'scanner_realtime.log';
$config['quarantine_dir'] = SB . 'files/quarantine/'; 
$config['log_file_url'] = SB.'/files/' . $config['log_file_relative'];
$config['realtime_log_full_path'] = SB . 'files/' . $config['realtime_log_relative'];
$config['log_file_full_path'] = SB . 'files/' . $config['log_file_relative'];
$config['cache_list_full_path'] = SB . 'files/' . $config['cache_list_relative'];

$config['allowed_extensions'] = ['jpg', 'jpeg', 'png', 'gif'];
$config['suspicious_strings'] = [
    '<?php', 'phpinfo',
    'eval(',
    'system(',
    'shell_exec(',
    'base64_decode(',
    '$_POST[',
    '$_GET[',
    'GIF89a;<?php' 
];
$config['scan_limit'] = 10240;