<?php
/*
* @author Heru Subekti <https://github.com/heroesoebekti/>
* @copyright 2025 Heru Subekti
* @license GPL-3.0-or-later
* @File name      : scanner_prcess.php
*/

defined('INDEX_AUTH') OR die('Direct access not allowed!');

use RecursiveIteratorIterator as RII;
use RecursiveDirectoryIterator as RDI;
use FilesystemIterator as FI;

// IP based access limitation
require LIB . 'ip_based_access.inc.php';
include __DIR__ . '/scanner_config.php';

do_checkIP('smc');
do_checkIP('smc-system');

$can_read = utility::havePrivilege('system', 'r');
if (!$can_read) {
    echo json_encode(['status' => 'error', 'message' => __('You don\'t have enough privileges to access this area!')]);
    exit();
}

if (!is_dir($config['quarantine_dir'])) {
    @mkdir($config['quarantine_dir'], 0775, true);
}

if (isset($_POST['action'])) {
    if ($_POST['action'] === 'get_log') {
        $logContent = '';
        if (file_exists($config['log_file_full_path'])) {
            $logContent = file_get_contents($config['log_file_full_path']);
        } else {
            $logContent = __('Log file not found or empty.') . ' (' . $config['log_file_relative'] . ')';
        }
        echo json_encode(['status' => 'success', 'log' => $logContent]);
        exit();
    }

    if ($_POST['action'] === 'delete_log') {
        $deleted_log = 0;
        if (file_exists($config['log_file_full_path'])) {
            if (@unlink($config['log_file_full_path'])) {
                $deleted_log = 1;
            }
        }
        if (file_exists($config['cache_list_full_path'])) {
            @unlink($config['cache_list_full_path']);
        }
        
        if ($deleted_log) {
            echo json_encode(['status' => 'success', 'message' => __('Scan report successfully deleted.'), 'count' => 1]);
        } else {
            echo json_encode(['status' => 'success', 'message' => __('Scan report not found, nothing to delete.'), 'count' => 0]);
        }
        exit();
    }

    if ($_POST['action'] === 'quarantine') {
        if (!class_exists('\ZipArchive')) {
            echo json_encode(['status' => 'error', 'message' => __('PHP Zip extension is not enabled. Cannot perform quarantine compression.')]);
            exit();
        }

        $quarantined_count = 0;
        $quarantined_list = [];
        $files_to_delete = [];

        if (!file_exists($config['cache_list_full_path'])) {
             echo json_encode([
                'status' => 'error', 
                'message' => __('No suspicious file list found. Please run a scan first.'),
                'count' => 0
            ]);
            exit();
        }

        $suspicious_files_relative = file($config['cache_list_full_path'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        if (empty($suspicious_files_relative)) {
            @unlink($config['cache_list_full_path']);
            echo json_encode([
                'status' => 'success', 
                'message' => __('No suspicious files to quarantine found in cache.'),
                'count' => 0
            ]);
            exit();
        }

        $zip_filename = 'quarantine_' . date('Ymd_His') . '.zip';
        $zip_path = $config['quarantine_dir'] . $zip_filename;

        $zip = new \ZipArchive();
        if ($zip->open($zip_path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== TRUE) {
            echo json_encode([
                'status' => 'error', 
                'message' => __('Failed to create ZIP archive in quarantine directory. Check permissions.') . ' (' . $zip_path . ')',
                'count' => 0
            ]);
            exit();
        }

        foreach ($suspicious_files_relative as $relative_path) {
            $full_path = SB . $relative_path;   
            if (file_exists($full_path)) {
                if ($zip->addFile($full_path, $relative_path)) {
                    $files_to_delete[] = $full_path;
                    $quarantined_list[] = $relative_path;
                } 
            }
        }

        if (count($files_to_delete) > 0) {
            $zip_close_success = $zip->close();
        } else {
            $zip->close(); 
            @unlink($zip_path);
            $zip_close_success = true;
        }

        if ($zip_close_success) {
            foreach ($files_to_delete as $file_to_unlink) {
                if (@unlink($file_to_unlink)) {
                    $quarantined_count++;
                }
            }
            @unlink($config['cache_list_full_path']);
            echo json_encode([
                'status' => 'success', 
                'message' => __('Successfully quarantined') . " $quarantined_count " . __('files into archive') . " <strong>$zip_filename</strong>.",
                'count' => $quarantined_count,
                'files' => $quarantined_list,
                'archive' => $zip_filename
            ]);
            exit();
        } else {
            @unlink($zip_path); 
            @unlink($config['cache_list_full_path']);
            echo json_encode([
                'status' => 'error', 
                'message' => __('Failed to finalize ZIP archive. Original files were NOT deleted.') . ' (' . $zip_path . ')',
                'count' => 0
            ]);
            exit();
        }
    }
}


function scan_file($filepath, $config, &$verbose_output) {
    $findings = [];
    $file_extension = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));

    if (!in_array($file_extension, $config['allowed_extensions']) || !is_readable($filepath)) {
        return $findings; 
    }
    
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $filepath);
        finfo_close($finfo);

        if (substr($mime_type, 0, 6) !== 'image/') { 
            $findings[] = __('SUSPICIOUS MIME TYPE') . ": $mime_type (" . __('Extension') . " $file_extension, " . __('but MIME type is not an image') . ")";
        }
    } 

    $file_content = file_get_contents($filepath, false, null, 0, $config['scan_limit']);
    
    if ($file_content !== false) {
        foreach ($config['suspicious_strings'] as $string) {
            if (strpos($file_content, $string) !== false) {
                $findings[] = __('CODE FOUND: Suspicious string') . " '$string' " . __('detected at the beginning of the file.');
            }
        }
    } else {
        $findings[] = __('FAILED TO READ FILE: Check read permission.');
    }

    return $findings;
}

if (!isset($_POST['scan_dirs']) || empty($_POST['scan_dirs'])) {
    echo json_encode(['status' => 'error', 'message' => __('No directories selected for scanning.')]);
    exit();
}

$scan_dirs_input = (array)$_POST['scan_dirs'];
$valid_scan_dirs = [];
$report_header = date('Y-m-d H:i:s') . " --- " . __('SUSPICIOUS FINDINGS REPORT (RECURSIVE)') . " ---\n";
$report_body = "";
$verbose_output = $report_header;
$total_scanned = 0;
$total_tampered = 0;
$files_to_quarantine = []; 

if (file_exists($config['cache_list_full_path'])) {
    @unlink($config['cache_list_full_path']);
}

foreach ($scan_dirs_input as $dir) {
    $dir = trim($dir);
    if (isset($config['available_dirs'][$dir]) && is_dir(SB . $dir)) {
        $valid_scan_dirs[] = SB . $dir;
        $verbose_output .= __('Scanning directory') . ": " . $dir . "...\n";
    } else {
        $verbose_output .= __('Invalid or not found directory') . ": " . $dir . "\n";
    }
}

if (empty($valid_scan_dirs)) {
    echo json_encode(['status' => 'error', 'message' => __('All selected directories are invalid or not found.')]);
    exit();
}

try {
    foreach ($valid_scan_dirs as $scan_dir_path) {
        $iterator = new RII(new RDI($scan_dir_path, FI::SKIP_DOTS), RII::SELF_FIRST);

        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile()) {
                $filepath = $fileinfo->getRealPath();
                $file_ext = strtolower($fileinfo->getExtension());
                
                if (!in_array($file_ext, $config['allowed_extensions'])) {
                    continue; 
                }

                $total_scanned++;
                $findings = scan_file($filepath, $config, $verbose_output);

                if (!empty($findings)) {
                    $total_tampered++;
                    $relative_filepath = str_replace(SB, '', $filepath);
                    $files_to_quarantine[] = $relative_filepath; 
                    $report_body .= "\n[ FILE: " . $relative_filepath . " ]\n"; 
                    $report_body .= "  ⚠️ " . __('STATUS: SUSPICIOUS (Potential Tampering/Code Injection)') . "\n";
                    $report_body .= "  " . __('FINDINGS') . ":\n";
                    foreach ($findings as $finding) {
                        $report_body .= "    - $finding\n";
                    }
                    $verbose_output .= "  [FILE: " . $relative_filepath . "] " . __('SUSPICIOUS! See log for details.') . "\n";
                } 
            }
        }
    }

} catch (Exception $e) {
    $report_body .= "\n❌ " . __('Error during directory iteration') . ": " . $e->getMessage() . "\n";
    $verbose_output .= "\n" . __('Error during directory iteration') . ": " . $e->getMessage() . "\n";
    $status = 'error';
    $message = __('Error during directory iteration') . ': ' . $e->getMessage();
}


$final_report = $report_header;
if (empty($report_body)) {
    $final_report .= "\n✅ " . __('NO SUSPICIOUS IMAGE FILES FOUND.') . "\n";
} else {
    $final_report .= $report_body;
}

if (!empty($files_to_quarantine)) {
    file_put_contents($config['cache_list_full_path'], implode("\n", $files_to_quarantine));
}

if (file_put_contents($config['log_file_full_path'], $final_report, FILE_APPEND) !== false) {
    $verbose_output .= "\n" . __('Scan Finished.') . "\n";
    $verbose_output .= __('Total image files scanned') . ": $total_scanned\n";
    $verbose_output .= __('Total **suspicious** files recorded') . ": $total_tampered\n";
    $status = 'success';
    $message = __('Scan finished.');
} else {
    $verbose_output .= __('Error: Failed to save report to') . " '" . $config['log_file_full_path'] . "'. " . __('Check write permission.') . "\n";
    $status = 'error';
    $message = __('Failed to save log report.');
}

// Send result as JSON
echo json_encode([
    'status' => $status,
    'message' => $message,
    'scanned' => $total_scanned,
    'tampered' => $total_tampered,
   // 'log_file' => $config['log_file_url'],
    'scanned_dirs' => implode(', ', array_keys(array_intersect_key($config['available_dirs'], array_flip($scan_dirs_input)))),
    'verbose' => htmlspecialchars($verbose_output) 
]);