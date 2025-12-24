<?php
/*
* @author Heru Subekti <https://github.com/heroesoebekti/>
* @copyright 2025 Heru Subekti
* @license GPL-3.0-or-later
* @File name      : index.php
*/

defined('INDEX_AUTH') OR die('Direct access not allowed!');

use SLiMS\Url;

// IP based access limitation
require LIB . 'ip_based_access.inc.php';
do_checkIP('smc');
do_checkIP('smc-system');
// start the session
require SB . 'admin/default/session.inc.php';
require __DIR__ . '/scanner_config.php';

$can_read = utility::havePrivilege('system', 'r');
if (!$can_read) {
    die('<div class="errorBox">'.__('You don\'t have enough privileges to access this area!').'</div>');
}

if(isset($_POST['is_ajax'])){
   include __DIR__ . '/scanner_process.php';
   exit();
}

$available_dirs = $config['available_dirs'];
$log_file_url = $config['log_file_url'];
$log_file_full_path = $config['log_file_full_path'];
?>

<style>
#log-content-modal {
    background-color: #f8f9fa; 
    border: 1px solid #ccc; 
    padding: 10px;
    white-space: pre-wrap;
    font-family: monospace;
    max-height: 50vh;
    overflow-y: scroll;
}
</style>

<div class="menuBox">
    <div class="menuBoxInner printIcon">
        <div class="per_title">
            <h2><?php echo __('Images Scanner'); ?></h2>
        </div>
        <div class="infoBox alert alert-info">
            <?php echo __('Select the directories to be scanned. The scanning process is executed in the backend, and the results are displayed here.'); ?>
            <br><?php echo __('The log report is saved in'); ?>: <strong><?php echo str_replace(SB, '', $log_file_full_path); ?></strong>
            <br><?php echo __('Suspicious files will be moved to the quarantine directory'); ?>: <strong><?php echo str_replace(SB, '', $config['quarantine_dir']); ?></strong>
        </div>

        <div id="scan-status-message">
        </div>

        <div class="sub_section">
            <form name="scan" id="scan-form" method="post">
                <input type="hidden" name="is_ajax" value="1"/>
                
                <p><strong><?php echo __('Select Directories to Scan'); ?>:</strong></p>
                <div class="form-group" style="border: 1px solid #ccc; padding: 10px; border-radius: 4px;">
                    <?php foreach ($available_dirs as $dir_key => $dir_name): ?>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="scan_dirs[]" value="<?php echo $dir_key; ?>" id="check_<?php echo str_replace('/', '', $dir_key); ?>" checked>
                            <label class="form-check-label" for="check_<?php echo str_replace('/', '', $dir_key); ?>">
                                <?php echo $dir_key; ?> (<?php echo $dir_name; ?>)
                            </label>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <button type="submit" id="doScan" class="s-btn btn btn-success" style="margin-top: 10px;">
                        </span>
                    <span id="scan-text"><?php echo __('Start Scanning'); ?></span>
                </button>

                <button type="button" id="showLog" class="s-btn btn btn-primary" style="margin-top: 10px;">
                    <?php echo __('View Latest Scan Report'); ?>
                </button>

                <button type="button" id="deleteLog" class="s-btn btn btn-danger" style="margin-top: 10px;">
                    <?php echo __('Delete Scan Report'); ?>
                </button>

            </form>
            <div id="action-buttons-container" style="margin-top: 10px;">
                </div>
        </div>

        <div id="verbose-output-container" style="background-color: #000; color: #0f0; padding: 15px; margin-top: 20px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: scroll; font-size: 13px; display: none;">
            </div>
        
    </div>
</div>

<div class="modal fade" id="logModal" tabindex="-1" role="dialog" aria-labelledby="logModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="logModalLabel"><?php echo __('Latest Scan Report'); ?></h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
        <div id="log-content-modal"><?php echo __('Loading report...'); ?></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal"><?php echo __('Close'); ?></button>
      </div>
    </div>
  </div>
</div>

<script>
$(document).ready(function() {
    const PROCESS_URL = '<?=$_SERVER['REQUEST_URI']?>';
    const actionButtonsContainer = $('#action-buttons-container');
    function handleAction(action, successMessage) {
        if (action !== 'delete_log' && action !== 'quarantine') return;
        const submitButton = $('#' + (action === 'delete_log' ? 'deleteLog' : 'quarantineFiles'));
        if (action !== 'delete_log' && !confirm('<?php echo __('Are you sure you want to quarantine all suspicious files?'); ?>')) {
            return;
        }
        submitButton.prop('disabled', true).text('<?php echo __('Processing...'); ?>');
        $('#scan-status-message').html('');
        
        $.ajax({
            url: PROCESS_URL,
            type: 'POST',
            data: { is_ajax: 1, action: action },
            dataType: 'json',
            success: function(response) {
                if (response.status === 'success') {
                    toastr.success(successMessage.replace('{{count}}', response.count || 0), '<?php echo __('Success'); ?>', {timeOut: 5000}); 
                    $('#scan-status-message').html('');
                    if (action === 'quarantine') {
                        actionButtonsContainer.empty(); 
                    }
                } else {
                    toastr.error(response.message || '<?php echo __('Unknown error occurred.'); ?>', '<?php echo __('Error'); ?>', {timeOut: 5000});
                    $('#scan-status-message').html('');
                }
            },
            error: function() {
                toastr.error('<?php echo __('Network/Server Error: Failed to complete action.'); ?>', '<?php echo __('Error'); ?>', {timeOut: 5000});
                $('#scan-status-message').html('');
            },
            complete: function() {
                submitButton.prop('disabled', false).text(action === 'delete_log' ? '<?php echo __('Delete Scan Report'); ?>' : '<?php echo __('Quarantine Suspicious Files'); ?>');
            }
        });
    }

    $('#scan-form').on('submit', function(e) {
        e.preventDefault(); 
        $('#scan-status-message').html('');
        actionButtonsContainer.empty();
        const verboseContainer = $('#verbose-output-container');
        verboseContainer.html('<p><?php echo __('Starting scan...'); ?></p>').hide();

        const form = $(this);
        const submitButton = $('#doScan');
        const selectedDirs = form.find('input[name="scan_dirs[]"]:checked').length;

        if (selectedDirs === 0) {
            toastr.warning('<?php echo __('Warning: You must select at least one directory to scan.'); ?>', '<?php echo __('Warning'); ?>', {timeOut: 5000});
            return;
        }

        submitButton.prop('disabled', true);
        $('#scan-text').text('<?php echo __('Scanning...'); ?>');
        verboseContainer.show();
        verboseContainer.html('<span><?php echo __('Connection successful. Scanning process started in the backend...'); ?></span><br/>');
        $.ajax({
            url:  PROCESS_URL, 
            type: 'POST',
            data: form.serialize(), 
            dataType: 'json',
            success: function(response) {
                verboseContainer.html(response.verbose);
                $('#scan-status-message').html('');                
                if (response.status === 'success') {
                    const baseMessage = '<?php echo __('Total'); ?> ' + response.scanned + ' <?php echo __('files scanned.'); ?>';
                    if (response.tampered > 0) {
                        toastr.error('<?php echo __('Found'); ?> **' + response.tampered + '** <?php echo __('suspicious files!'); ?> ' + baseMessage, '<?php echo __('Scan Finished'); ?>', {timeOut: 10000});
                        
                        const quarantineButton = $('<button>')
                            .attr('type', 'button')
                            .attr('id', 'quarantineFiles')
                            .addClass('s-btn btn btn-warning')
                            .text('<?php echo __('Quarantine Suspicious Files'); ?> (' + response.tampered + ')')
                            .on('click', function() {
                                handleAction('quarantine', '<?php echo __('Successfully quarantined'); ?> {{count}} <?php echo __('files.'); ?>');
                            });
                        actionButtonsContainer.append(quarantineButton);
                    } else {
                        toastr.success('<?php echo __('NO'); ?> <?php echo __('suspicious files found.'); ?> ' + baseMessage, '<?php echo __('Scan Finished'); ?>', {timeOut: 5000});
                    }
                } else {
                    toastr.error(response.message || '<?php echo __('Unknown error occurred.'); ?>', '<?php echo __('Scan Error'); ?>', {timeOut: 5000});
                }
            },
            error: function(xhr, status, error) {
                const errorMessage = '<?php echo __('Network/Server Error: Failed to complete scan. Status'); ?>: ' + status + '.';
                toastr.error(errorMessage, '<?php echo __('Scan Error'); ?>', {timeOut: 10000});
                verboseContainer.append('<span style="color: #f00;">\n' + errorMessage + ' <?php echo __('Check browser console.'); ?></span>');
                $('#scan-status-message').html('');
                console.error("AJAX Error:", status, error, xhr.responseText);
            },
            complete: function() {
                submitButton.prop('disabled', false);
                $('#scan-text').text('<?php echo __('Start Scanning'); ?>');
            }
        });
    });

    $('#showLog').on('click', function() {
        const logContentContainer = $('#log-content-modal');
        logContentContainer.html('<?php echo __('Loading report...'); ?>');
        $.ajax({
            url: PROCESS_URL,
            type: 'POST',
            data: { is_ajax: 1, action: 'get_log' },
            dataType: 'json',
            success: function(response) {
                if (response.status === 'success') {
                    logContentContainer.text(response.log); 
                } else {
                    logContentContainer.html('<div class="alert alert-danger"><?php echo __('Error loading report'); ?>: ' + response.message + '</div>');
                }
                $('#logModal').modal('show');
            },
            error: function() {
                logContentContainer.html('<div class="alert alert-danger"><?php echo __('Failed to fetch log report from server.'); ?></div>');
                $('#logModal').modal('show');
            }
        });
    });
    $('#deleteLog').on('click', function() {
        if (confirm('<?php echo __('Are you sure you want to delete the scan report?'); ?>')) {
            handleAction('delete_log', '<?php echo __('Scan report successfully deleted.'); ?>');
        }
    });
});
</script>