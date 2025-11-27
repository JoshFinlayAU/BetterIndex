<?php
// BetterIndex - Beautiful Directory Listing and File Manager
// Single file with embedded HTML, CSS, JavaScript, and PHP

// Error display settings
ini_set('display_errors', 0);
error_reporting(0);

// Apply security headers early
setSecurityHeaders();

/* ======== Configuration Options ======== */

// Basic Configuration
$base_path = __DIR__;
$allowed_extensions = ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'tbn', 'html', 'css', 'js', 'php', 'json', 'xml', 'md']; // or, change this ['*'] to allow all file types
$max_file_size = 100 * 1024 * 1024; // 100MB

// UI Configuration
$page_title = 'Index of ' . sanitizeOutput(calculateRelativePath() ?: '/'); // or, change this to be the page title you want to have
$header_title = "BetterIndex"
$default_theme = 'light'; // 'light' or 'dark' or 'blue' or 'green' or 'purple'.. dark mode is always 'dark', but light mode is any other value including 'light'
$default_view = 'grid'; // 'grid', 'list', or 'compact'
$hide_dotfiles = true; // Hide files and folders starting with '.'

// Security Configuration
$auth_enabled = true; // Set to true to enable authentication
$auth_db_path = __DIR__ . '/.betterindex_users.db';
$login_attempts_limit = 5; // Max failed login attempts before lockout
$lockout_duration = 300; // Lockout duration in seconds (5 minutes)
$remember_me_duration = 2592000; // Remember me duration in seconds (30 days)
$csrf_validation = true; // Set to true to enable CSRF validation

// Log Configuration
$log_activity = true; // Set to true to log file activity (downloads and views)
$log_file_path = __DIR__ . '/.betterindex_activity.log';
$log_max_lines = 1000; // Maximum lines to keep in log file (0 = no trimming)

// File Operations Configuration
$trash_folder = $base_path . '/.betterindex_trash';
$max_upload_size = $max_file_size; // Use same limit as download
$allowed_upload_extensions = $allowed_extensions; // Use same extensions as viewing
$dangerous_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'pht', 'phar', 'exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js', 'jar', 'sh', 'py', 'pl', 'rb'];
$check_file_content = true; // check file content for dangerous code
$file_content_regex = '/<\?php|<script|javascript:|vbscript:/i'; // basic regex checks, not comprehensive

// Theme Configuration - Customize colors here
$theme_config = [
    'light' => [
        'bg_primary' => '#ffffff',
        'bg_secondary' => '#f8f9fa',
        'bg_tertiary' => '#e9ecef',
        'text_primary' => '#212529',
        'text_secondary' => '#6c757d',
        'text_muted' => '#adb5bd',
        'accent_color' => '#5a2ca0',
        'accent_hover' => '#7950f2',
        'success_color' => '#28a745',
        'success_hover' => '#218838',
        'warning_color' => '#ffc107',
        'warning_hover' => '#e0a800',
        'danger_color' => '#dc3545',
        'danger_hover' => '#c82333',
        'border_color' => '#dee2e6',
        'shadow' => '0 0.125rem 0.25rem rgba(0, 0, 0, 0.075)',
        'shadow_lg' => '0 0.5rem 1rem rgba(0, 0, 0, 0.15)',
        'overlay' => 'rgba(0, 0, 0, 0.5)'
    ],
    'dark' => [
        'bg_primary' => '#1a1a1a',
        'bg_secondary' => '#2d2d2d',
        'bg_tertiary' => '#404040',
        'text_primary' => '#ffffff',
        'text_secondary' => '#b3b3b3',
        'text_muted' => '#808080',
        'accent_color' => '#0d6efd',
        'accent_hover' => '#0b5ed7',
        'success_color' => '#198754',
        'success_hover' => '#157347',
        'warning_color' => '#ffc107',
        'warning_hover' => '#ffca2c',
        'danger_color' => '#dc3545',
        'danger_hover' => '#bb2d3b',
        'border_color' => '#495057',
        'shadow' => '0 0.125rem 0.25rem rgba(0, 0, 0, 0.3)',
        'shadow_lg' => '0 0.5rem 1rem rgba(0, 0, 0, 0.4)',
        'overlay' => 'rgba(0, 0, 0, 0.7)'
    ],
    'blue' => [
        'bg_primary' => '#f0f8ff',
        'bg_secondary' => '#e6f3ff',
        'bg_tertiary' => '#cce7ff',
        'text_primary' => '#1e3a8a',
        'text_secondary' => '#3b82f6',
        'text_muted' => '#6b7280',
        'accent_color' => '#2563eb',
        'accent_hover' => '#1d4ed8',
        'success_color' => '#059669',
        'success_hover' => '#047857',
        'warning_color' => '#d97706',
        'warning_hover' => '#b45309',
        'danger_color' => '#dc2626',
        'danger_hover' => '#b91c1c',
        'border_color' => '#bfdbfe',
        'shadow' => '0 0.125rem 0.25rem rgba(37, 99, 235, 0.1)',
        'shadow_lg' => '0 0.5rem 1rem rgba(37, 99, 235, 0.2)',
        'overlay' => 'rgba(30, 58, 138, 0.5)'
    ],
    'green' => [
        'bg_primary' => '#f0fdf4',
        'bg_secondary' => '#dcfce7',
        'bg_tertiary' => '#bbf7d0',
        'text_primary' => '#14532d',
        'text_secondary' => '#16a34a',
        'text_muted' => '#6b7280',
        'accent_color' => '#22c55e',
        'accent_hover' => '#16a34a',
        'success_color' => '#059669',
        'success_hover' => '#047857',
        'warning_color' => '#d97706',
        'warning_hover' => '#b45309',
        'danger_color' => '#dc2626',
        'danger_hover' => '#b91c1c',
        'border_color' => '#a7f3d0',
        'shadow' => '0 0.125rem 0.25rem rgba(34, 197, 94, 0.1)',
        'shadow_lg' => '0 0.5rem 1rem rgba(34, 197, 94, 0.2)',
        'overlay' => 'rgba(20, 83, 45, 0.5)'
    ],
    'purple' => [
        'bg_primary' => '#faf5ff',
        'bg_secondary' => '#f3e8ff',
        'bg_tertiary' => '#e9d5ff',
        'text_primary' => '#581c87',
        'text_secondary' => '#7c3aed',
        'text_muted' => '#6b7280',
        'accent_color' => '#8b5cf6',
        'accent_hover' => '#7c3aed',
        'success_color' => '#059669',
        'success_hover' => '#047857',
        'warning_color' => '#d97706',
        'warning_hover' => '#b45309',
        'danger_color' => '#dc2626',
        'danger_hover' => '#b91c1c',
        'border_color' => '#c4b5fd',
        'shadow' => '0 0.125rem 0.25rem rgba(139, 92, 246, 0.1)',
        'shadow_lg' => '0 0.5rem 1rem rgba(139, 92, 246, 0.2)',
        'overlay' => 'rgba(88, 28, 135, 0.5)'
    ]
];

/* ======== End of configuration options ======== */

// Set comprehensive security headers
function setSecurityHeaders() {
    // Prevent clickjacking
    header('X-Frame-Options: DENY');
    
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Enable XSS protection
    header('X-XSS-Protection: 1; mode=block');
    
    // Referrer policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy - restrictive but functional
    $csp = "default-src 'self'; " .
           "script-src 'self' 'unsafe-inline'; " .
           "style-src 'self' 'unsafe-inline'; " .
           "img-src 'self' data:; " .
           "media-src 'self' data:; " .
           "object-src 'none'; " .
           "base-uri 'self'; " .
           "form-action 'self'; " .
           "frame-ancestors 'none'";
    header('Content-Security-Policy: ' . $csp);
    
    // HTTPS security (only if HTTPS is detected)
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    
    // Permissions policy (formerly Feature Policy)
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}


// Startup tests - Check file access permissions
function runStartupTests() {
    global $auth_enabled, $auth_db_path, $log_activity, $log_file_path;
    $errors = [];
    
    // Test database access if authentication is enabled
    if ($auth_enabled) {
        $db_dir = dirname($auth_db_path);
        if (!is_writable($db_dir)) {
            $errors[] = "Database directory not writable: {$db_dir}";
        } elseif (file_exists($auth_db_path) && !is_writable($auth_db_path)) {
            $errors[] = "Database file not writable: {$auth_db_path}";
        }
    }
    
    // Test log file access if logging is enabled
    if ($log_activity) {
        $log_dir = dirname($log_file_path);
        if (!is_writable($log_dir)) {
            $errors[] = "Log directory not writable: {$log_dir}";
        } elseif (file_exists($log_file_path) && !is_writable($log_file_path)) {
            $errors[] = "Log file not writable: {$log_file_path}";
        }
    }
    
    return $errors;
}

// Run startup tests
$startup_errors = runStartupTests();
if (!empty($startup_errors)) {
    die('<h3>BetterIndex Startup Error</h3><ul><li>' . implode('</li><li>', $startup_errors) . '</li></ul>');
}

// Security Functions
function sanitizePath($path) {
    // Remove null bytes and normalize path separators
    $path = str_replace(['\0', '\\'], ['', '/'], $path);
    
    // Remove any path traversal attempts
    $path = preg_replace('/\.{2,}/', '', $path);
    $path = str_replace(['../', '../', '..\\'], '', $path);
    
    // Remove leading/trailing slashes and normalize
    $path = trim($path, '/');
    
    // Split into parts and validate each
    $parts = explode('/', $path);
    $clean_parts = [];
    
    foreach ($parts as $part) {
        // Skip empty parts, dots, and any remaining traversal attempts
        if ($part === '' || $part === '.' || $part === '..' || strpos($part, '..') !== false) {
            continue;
        }
        
        // Only allow alphanumeric, hyphens, underscores, spaces, and dots (for extensions) -- does this break legitimate file names?? idk, lets wait and see.
        if (preg_match('/^[a-zA-Z0-9._\s-]+$/', $part)) {
            $clean_parts[] = $part;
        }
    }
    
    return implode('/', $clean_parts);
}

function validatePath($user_path, $base_path) {
    // Sanitize the user input first
    $clean_path = sanitizePath($user_path);
    
    // Build the full path
    $full_path = $base_path . ($clean_path ? '/' . $clean_path : '');
    
    // Get the real path (resolves symlinks and relative paths)
    // Use error suppression to handle open_basedir restrictions gracefully
    $real_path = @realpath($full_path);
    $real_base = $base_path ? @realpath($base_path) : false;
    
    // Ensure both paths exist and base path is valid
    if (!$real_base) {
        return false;
    }
    
    // If the target doesn't exist, check if parent directory is valid
    if (!$real_path) {
        $parent_dir = dirname($full_path);
        $real_parent = $parent_dir ? @realpath($parent_dir) : false;
        
        if (!$real_parent || strpos($real_parent, $real_base) !== 0) {
            return false;
        }
        
        // Return the sanitized path for non-existent files (for creation)
        return $full_path;
    }
    
    // Ensure the real path is within the base directory
    if (strpos($real_path, $real_base) !== 0) {
        return false;
    }
    
    // Additional check: ensure no directory traversal in the resolved path
    $relative_path = substr($real_path, strlen($real_base));
    if (strpos($relative_path, '..') !== false) {
        return false;
    }
    
    return $real_path;
}

function sanitizeOutput($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    global $csrf_validation;
    if (!$csrf_validation) return true;
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function generateRememberToken() {
    return bin2hex(random_bytes(32));
}

function storeRememberToken($pdo, $user_id, $token) {
    $hashed_token = password_hash($token, PASSWORD_DEFAULT);
    $expires = date('Y-m-d H:i:s', time() + 2592000); // 30 days
    
    $stmt = $pdo->prepare("INSERT OR REPLACE INTO remember_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
    return $stmt->execute([$user_id, $hashed_token, $expires]);
}

function validateRememberToken($pdo, $token) {
    $stmt = $pdo->prepare("SELECT user_id, token_hash FROM remember_tokens WHERE expires_at > datetime('now')");
    $stmt->execute();
    $tokens = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($tokens as $stored_token) {
        if (password_verify($token, $stored_token['token_hash'])) {
            return $stored_token['user_id'];
        }
    }
    
    return false;
}

function cleanupExpiredTokens($pdo) {
    $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE expires_at <= datetime('now')");
    $stmt->execute();
}

function validateUsername($username) {
    // Username must be 3-50 characters, alphanumeric plus underscore and hyphen
    return preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $username);
}

function validatePassword($password) {
    // Password must be at least 8 characters
    return strlen($password) >= 8;
}

function validateRole($role) {
    return in_array($role, ['admin', 'guest']);
}

function validateUserId($id) {
    return is_numeric($id) && intval($id) > 0;
}

function sanitizeFilename($filename) {
    // Remove only truly dangerous characters while preserving Unicode
    // Remove: null bytes, control characters, and Unix filesystem-reserved characters
    $filename = preg_replace('/[\x00-\x1F\x7F]/', '', $filename); // Remove control characters
    $filename = str_replace(['/', '\0'], '', $filename); // Remove path separator and null bytes
    
    // Remove leading/trailing dots and spaces for safety
    $filename = trim($filename, '. ');
    
    // Ensure we don't exceed filesystem byte limits (255 bytes for ext4/most Unix filesystems)
    // Use mb_strcut to safely truncate at byte boundary without breaking Unicode characters
    if (strlen($filename) > 255) {
        $filename = mb_strcut($filename, 0, 250, 'UTF-8'); // Leave some margin
        // Ensure we don't end with a partial character
        $filename = rtrim($filename, '. ');
    }
    
    // Prevent empty filenames
    if (empty($filename)) {
        $filename = 'file_' . uniqid();
    }
    
    return $filename;
}

function validateFileExtension($extension, $allowed_extensions) {
    if (in_array('*', $allowed_extensions)) {
        return true;
    }
    return in_array(strtolower($extension), array_map('strtolower', $allowed_extensions));
}

function validateFileSize($size, $max_size) {
    return is_numeric($size) && $size > 0 && $size <= $max_size;
}

// File Operations Functions (Admin Only)
function ensureTrashFolder($trash_folder) {
    if (!is_dir($trash_folder)) {
        if (!mkdir($trash_folder, 0755, true)) {
            return false;
        }
    }
    return true;
}

function validateFileOperation($user, $operation) {
    // Only admins can perform file operations
    return $user && $user['role'] === 'admin';
}

function secureFileUpload($file, $target_dir, $allowed_extensions, $max_size) {
    $errors = [];
    global $dangerous_extensions;
    global $check_file_content;
    global $file_content_regex;
    
    // Basic file validation
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        $errors[] = "Invalid file upload";
        return ['success' => false, 'errors' => $errors];
    }
    
    // Check file size
    if ($file['size'] > $max_size) {
        $errors[] = "File too large. Maximum size: " . formatFileSize($max_size);
        return ['success' => false, 'errors' => $errors];
    }
    
    // Sanitize filename
    $original_name = $file['name'];
    $safe_name = sanitizeFilename($original_name);
    
    if (empty($safe_name)) {
        $errors[] = "Invalid filename";
        return ['success' => false, 'errors' => $errors];
    }
    
    // Check file extension
    $extension = strtolower(pathinfo($safe_name, PATHINFO_EXTENSION));
    if (!validateFileExtension($extension, $allowed_extensions)) {
        $errors[] = "File type not allowed. Allowed: " . implode(', ', $allowed_extensions);
        return ['success' => false, 'errors' => $errors];
    }
    
    // Check for executable files and dangerous extensions
    if (in_array($extension, $dangerous_extensions)) {
        $errors[] = "Executable files are not allowed for security reasons";
        return ['success' => false, 'errors' => $errors];
    }
    
    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    // Check for script content in files
    if ($check_file_content) {
        $file_content = file_get_contents($file['tmp_name'], false, null, 0, 1024); // Read first 1KB
        if (preg_match($file_content_regex, $file_content)) {
            $errors[] = "File contains potentially dangerous content";
            return ['success' => false, 'errors' => $errors];
        }
    }
    
    // Generate unique filename if file exists
    $target_path = $target_dir . '/' . $safe_name;
    $counter = 1;
    while (file_exists($target_path)) {
        $name_parts = pathinfo($safe_name);
        $new_name = $name_parts['filename'] . '_' . $counter;
        if (isset($name_parts['extension'])) {
            $new_name .= '.' . $name_parts['extension'];
        }
        $target_path = $target_dir . '/' . $new_name;
        $counter++;
    }
    
    // Move uploaded file
    if (move_uploaded_file($file['tmp_name'], $target_path)) {
        // Set secure permissions
        chmod($target_path, 0644);
        return ['success' => true, 'filename' => basename($target_path), 'path' => $target_path];
    } else {
        $errors[] = "Failed to save uploaded file";
        return ['success' => false, 'errors' => $errors];
    }
}

function secureFileDelete($file_path, $trash_folder) {
    if (!file_exists($file_path)) {
        return ['success' => false, 'error' => 'File not found'];
    }
    
    if (!ensureTrashFolder($trash_folder)) {
        return ['success' => false, 'error' => 'Cannot create trash folder'];
    }
    
    $filename = basename($file_path);
    $trash_path = $trash_folder . '/' . date('Y-m-d_H-i-s') . '_' . $filename;
    
    // Ensure unique trash filename
    $counter = 1;
    while (file_exists($trash_path)) {
        $trash_path = $trash_folder . '/' . date('Y-m-d_H-i-s') . '_' . $counter . '_' . $filename;
        $counter++;
    }
    
    if (rename($file_path, $trash_path)) {
        return ['success' => true, 'trash_path' => $trash_path];
    } else {
        return ['success' => false, 'error' => 'Failed to move file to trash'];
    }
}

function secureFileRename($old_path, $new_name) {
    if (!file_exists($old_path)) {
        return ['success' => false, 'error' => 'File not found'];
    }
    
    $safe_name = sanitizeFilename($new_name);
    if (empty($safe_name)) {
        return ['success' => false, 'error' => 'Invalid filename'];
    }
    
    $dir = dirname($old_path);
    $new_path = $dir . '/' . $safe_name;
    
    if (file_exists($new_path)) {
        return ['success' => false, 'error' => 'File with that name already exists'];
    }
    
    if (rename($old_path, $new_path)) {
        return ['success' => true, 'new_path' => $new_path];
    } else {
        return ['success' => false, 'error' => 'Failed to rename file'];
    }
}

function createFolder($parent_dir, $folder_name) {
    $safe_name = sanitizeFilename($folder_name);
    if (empty($safe_name)) {
        return ['success' => false, 'error' => 'Invalid folder name'];
    }
    
    $folder_path = $parent_dir . '/' . $safe_name;
    
    if (file_exists($folder_path)) {
        return ['success' => false, 'error' => 'Folder already exists'];
    }
    
    if (mkdir($folder_path, 0755)) {
        return ['success' => true, 'path' => $folder_path];
    } else {
        return ['success' => false, 'error' => 'Failed to create folder'];
    }
}

function getTrashContents($trash_folder) {
    if (!is_dir($trash_folder)) {
        return [];
    }
    
    $items = [];
    $files = scandir($trash_folder);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..' || $file === '.htaccess') continue;
        
        $full_path = $trash_folder . '/' . $file;
        
        // Handle both files and directories in trash
        if (is_file($full_path) || is_dir($full_path)) {
            // Parse timestamp and original name from trash filename
            $parts = explode('_', $file, 3);
            $deleted_date = 'Unknown';
            $original_name = $file;
            
            if (count($parts) >= 3) {
                $deleted_date = str_replace('_', ' ', $parts[0] . ' ' . str_replace('-', ':', $parts[1]));
                $original_name = $parts[2];
            }
            
            // Calculate size (for directories, get total size)
            $size = 0;
            $type = 'file';
            if (is_dir($full_path)) {
                $type = 'folder';
                $size = getDirectorySize($full_path);
            } else {
                $size = filesize($full_path);
            }
            
            $items[] = [
                'trash_name' => $file,
                'original_name' => $original_name,
                'deleted_date' => $deleted_date,
                'size' => $size,
                'type' => $type,
                'path' => $full_path
            ];
        }
    }
    
    // Sort by deletion date (newest first)
    usort($items, function($a, $b) {
        return strcmp($b['deleted_date'], $a['deleted_date']);
    });
    
    return $items;
}

function getDirectorySize($dir) {
    $size = 0;
    if (is_dir($dir)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($files as $file) {
            if ($file->isFile()) {
                $size += $file->getSize();
            }
        }
    }
    return $size;
}

function restoreFromTrash($trash_path, $restore_dir) {
    if (!file_exists($trash_path)) {
        return ['success' => false, 'error' => 'File not found in trash'];
    }
    
    $trash_filename = basename($trash_path);
    $parts = explode('_', $trash_filename, 3);
    $original_name = count($parts) >= 3 ? $parts[2] : $trash_filename;
    
    $restore_path = $restore_dir . '/' . $original_name;
    
    // Handle name conflicts
    $counter = 1;
    while (file_exists($restore_path)) {
        $name_parts = pathinfo($original_name);
        $new_name = $name_parts['filename'] . '_restored_' . $counter;
        if (isset($name_parts['extension'])) {
            $new_name .= '.' . $name_parts['extension'];
        }
        $restore_path = $restore_dir . '/' . $new_name;
        $counter++;
    }
    
    if (rename($trash_path, $restore_path)) {
        return ['success' => true, 'restored_path' => $restore_path];
    } else {
        return ['success' => false, 'error' => 'Failed to restore file'];
    }
}

function emptyTrash($trash_folder) {
    if (!is_dir($trash_folder)) {
        return ['success' => true, 'deleted_count' => 0, 'files_deleted' => 0, 'folders_deleted' => 0];
    }
    
    $files_deleted = 0;
    $folders_deleted = 0;
    $files = scandir($trash_folder);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..' || $file === '.htaccess') continue;
        
        $file_path = $trash_folder . '/' . $file;
        
        if (is_file($file_path)) {
            if (unlink($file_path)) {
                $files_deleted++;
            }
        } elseif (is_dir($file_path)) {
            if (deleteDirectory($file_path)) {
                $folders_deleted++;
            }
        }
    }
    
    $total_deleted = $files_deleted + $folders_deleted;
    return [
        'success' => true, 
        'deleted_count' => $total_deleted,
        'files_deleted' => $files_deleted,
        'folders_deleted' => $folders_deleted
    ];
}

function deleteDirectory($dir) {
    if (!is_dir($dir)) {
        return false;
    }
    
    $files = array_diff(scandir($dir), array('.', '..'));
    
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            deleteDirectory($path);
        } else {
            unlink($path);
        }
    }
    
    return rmdir($dir);
}

function calculateRelativePath() {
    global $base_path;
    
    // Calculate relative path from web server root
    $document_root = $_SERVER['DOCUMENT_ROOT'] ?? '';
    $script_dir = dirname($_SERVER['SCRIPT_NAME']) ?? '';
    $current_web_path = $script_dir;

    // If we're in a subdirectory, show the path (with security validation)
    if (isset($_GET['dir']) && !empty($_GET['dir'])) {
        $safe_dir = sanitizePath($_GET['dir']);
        if ($safe_dir && validatePath($safe_dir, $base_path)) {
            $current_web_path = rtrim($script_dir, '/') . '/' . $safe_dir;
        }
    }
    return $current_web_path;
}

// Get current theme colors
function getThemeColors($theme_name = 'light') {
    global $theme_config;
    return $theme_config[$theme_name] ?? $theme_config['light'];
}

// Generate CSS variables from theme configuration
function generateThemeCSS($theme_name = 'light') {
    $colors = getThemeColors($theme_name);
    $css = ":root {\n";
    foreach ($colors as $key => $value) {
        $css_var = '--' . str_replace('_', '-', $key);
        $css .= "    {$css_var}: {$value};\n";
    }
    $css .= "}\n";
    return $css;
}

// Authentication Functions
function initDatabase($db_path) {
    try {
        $pdo = new PDO('sqlite:' . $db_path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Create users table
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'guest',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Create login_attempts table for rate limiting
        $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            success INTEGER DEFAULT 0,
            attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Create remember_tokens table for secure remember me functionality
        $pdo->exec("CREATE TABLE IF NOT EXISTS remember_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )");
        
        // Check if admin user exists, if not create default
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role = 'admin'");
        $stmt->execute();
        $admin_count = $stmt->fetchColumn();
        
        if ($admin_count == 0) {
            // Generate a secure random password for initial admin user
            $initial_password = "admin123"; // generic default password
            $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
            $stmt->execute(['admin', password_hash($initial_password, PASSWORD_DEFAULT), 'admin']);
        }
        
        return $pdo;
    } catch (PDOException $e) {
        error_log("BetterIndex Database Error: " . $e->getMessage());
        return false;
    }
}

function checkLoginAttempts($pdo, $ip_address, $limit, $lockout_duration) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts 
                          WHERE ip_address = ? AND success = 0 
                          AND attempt_time > datetime('now', '-' || ? || ' seconds')");
    $stmt->execute([$ip_address, $lockout_duration]);
    $failed_attempts = $stmt->fetchColumn();
    
    return $failed_attempts < $limit;
}

function logLoginAttempt($pdo, $ip_address, $username, $success) {
    $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)");
    $stmt->execute([$ip_address, $username, $success ? 1 : 0]);
}

function authenticateUser($pdo, $username, $password) {
    $stmt = $pdo->prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password_hash'])) {
        return $user;
    }
    return false;
}

function logActivity($log_file_path, $action, $file_path, $user_info, $ip_address) {
    global $log_max_lines;
    
    $log_entry = date('Y-m-d H:i:s') . " | IP: $ip_address | User: " . 
                ($user_info ? $user_info['username'] . " (" . $user_info['role'] . ")" : "Anonymous") . 
                " | Action: $action | File: $file_path" . PHP_EOL;
    
    // Append the new log entry
    file_put_contents($log_file_path, $log_entry, FILE_APPEND | LOCK_EX);
    
    // Trim log file if max_lines is set and > 0
    if ($log_max_lines > 0) {
        trimLogFile($log_file_path, $log_max_lines);
    }
}

function trimLogFile($log_file_path, $max_lines) {
    if (!file_exists($log_file_path)) {
        return;
    }
    
    // Check file size first to avoid loading huge files into memory
    $file_size = filesize($log_file_path);
    if ($file_size > 10 * 1024 * 1024) { // If log file > 10MB, truncate more aggressively
        $max_lines = min($max_lines, 500);
    }
    
    $lines = file($log_file_path, FILE_IGNORE_NEW_LINES);
    $line_count = count($lines);
    
    // Only trim if we exceed the maximum
    if ($line_count > $max_lines) {
        // Keep the most recent max_lines entries
        $trimmed_lines = array_slice($lines, -$max_lines);
        
        // Write back to file
        file_put_contents($log_file_path, implode(PHP_EOL, $trimmed_lines) . PHP_EOL, LOCK_EX);
    }
}

// Handle file operations (Admin only)
if ($auth_enabled) {
    // Configure session security settings before starting session
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', 1);
    ini_set('session.save_handler', 'files');
    ini_set('session.save_path', sys_get_temp_dir());
    
    // Start session first to check user permissions
    session_start();
    $current_user = $_SESSION['user'] ?? null;
    
    // Process file operations for authenticated admin users
    if ($current_user && validateFileOperation($current_user, 'any')) {
        global $base_path, $trash_folder, $allowed_upload_extensions, $max_upload_size, $log_activity, $log_file_path;
        
        // Handle file upload
        if (isset($_POST['action']) && $_POST['action'] === 'upload' && isset($_FILES['file'])) {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $upload_error = "Invalid request. Please try again.";
            } else {
                $target_dir = isset($_POST['target_dir']) ? validatePath($_POST['target_dir'], $base_path) : $base_path;
                if (!$target_dir) {
                    $upload_error = "Invalid target directory";
                } else {
                    $result = secureFileUpload($_FILES['file'], $target_dir, $allowed_upload_extensions, $max_upload_size);
                    if ($result['success']) {
                        if ($log_activity) {
                            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            logActivity($log_file_path, 'UPLOAD', $result['filename'], $current_user, $ip_address);
                        }
                        $upload_success = "File uploaded successfully: " . $result['filename'];
                    } else {
                        $upload_error = implode(', ', $result['errors']);
                    }
                }
            }
        }
        
        // Handle file deletion
        if (isset($_POST['action']) && $_POST['action'] === 'delete' && isset($_POST['file_path'])) {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $operation_error = "Invalid request. Please try again.";
            } else {
                $file_path = validatePath($_POST['file_path'], $base_path);
                if (!$file_path) {
                    $operation_error = "Invalid file path";
                } else {
                    $result = secureFileDelete($file_path, $trash_folder);
                    if ($result['success']) {
                        if ($log_activity) {
                            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            logActivity($log_file_path, 'DELETE', $_POST['file_path'], $current_user, $ip_address);
                        }
                        $operation_success = "File moved to trash successfully";
                    } else {
                        $operation_error = $result['error'];
                    }
                }
            }
        }
        
        // Handle file rename
        if (isset($_POST['action']) && $_POST['action'] === 'rename' && isset($_POST['old_path']) && isset($_POST['new_name'])) {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $operation_error = "Invalid request. Please try again.";
            } else {
                $old_path = validatePath($_POST['old_path'], $base_path);
                if (!$old_path) {
                    $operation_error = "Invalid file path";
                } else {
                    $result = secureFileRename($old_path, $_POST['new_name']);
                    if ($result['success']) {
                        if ($log_activity) {
                            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            logActivity($log_file_path, 'RENAME', $_POST['old_path'] . ' -> ' . basename($result['new_path']), $current_user, $ip_address);
                        }
                        $operation_success = "File renamed successfully";
                    } else {
                        $operation_error = $result['error'];
                    }
                }
            }
        }
        
        // Handle folder creation
        if (isset($_POST['action']) && $_POST['action'] === 'create_folder' && isset($_POST['folder_name'])) {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $operation_error = "Invalid request. Please try again.";
            } else {
                $parent_dir = isset($_POST['parent_dir']) ? validatePath($_POST['parent_dir'], $base_path) : $base_path;
                if (!$parent_dir) {
                    $operation_error = "Invalid parent directory";
                } else {
                    $result = createFolder($parent_dir, $_POST['folder_name']);
                    if ($result['success']) {
                        if ($log_activity) {
                            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            logActivity($log_file_path, 'CREATE_FOLDER', $_POST['folder_name'], $current_user, $ip_address);
                        }
                        $operation_success = "Folder created successfully";
                    } else {
                        $operation_error = $result['error'];
                    }
                }
            }
        }
        
        // Handle trash operations
        if (isset($_POST['action']) && $_POST['action'] === 'restore_file' && isset($_POST['trash_file'])) {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $operation_error = "Invalid request. Please try again.";
            } else {
                $trash_path = $trash_folder . '/' . basename($_POST['trash_file']); // Sanitize path
                $restore_dir = isset($_POST['restore_dir']) ? validatePath($_POST['restore_dir'], $base_path) : $base_path;
                if (!$restore_dir) {
                    $operation_error = "Invalid restore directory";
                } else {
                    $result = restoreFromTrash($trash_path, $restore_dir);
                    if ($result['success']) {
                        if ($log_activity) {
                            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                            logActivity($log_file_path, 'RESTORE', basename($result['restored_path']), $current_user, $ip_address);
                        }
                        $operation_success = "File restored successfully";
                    } else {
                        $operation_error = $result['error'];
                    }
                }
            }
        }
        
        // Handle empty trash
        if (isset($_POST['action']) && $_POST['action'] === 'empty_trash') {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!validateCSRFToken($csrf_token)) {
                $operation_error = "Invalid request. Please try again.";
            } else {
                $result = emptyTrash($trash_folder);
                if ($result['success']) {
                    if ($log_activity) {
                        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                        $log_message = $result['files_deleted'] . ' files, ' . $result['folders_deleted'] . ' folders';
                        logActivity($log_file_path, 'EMPTY_TRASH', $log_message, $current_user, $ip_address);
                    }
                    
                    // Create detailed success message
                    $message_parts = [];
                    if ($result['files_deleted'] > 0) {
                        $message_parts[] = $result['files_deleted'] . ' file' . ($result['files_deleted'] != 1 ? 's' : '');
                    }
                    if ($result['folders_deleted'] > 0) {
                        $message_parts[] = $result['folders_deleted'] . ' folder' . ($result['folders_deleted'] != 1 ? 's' : '');
                    }
                    
                    if (!empty($message_parts)) {
                        $operation_success = "Trash emptied successfully. Deleted " . implode(' and ', $message_parts) . ".";
                    } else {
                        $operation_success = "Trash was already empty.";
                    }
                } else {
                    $operation_error = "Failed to empty trash";
                }
            }
            
            // Return JSON response for AJAX requests
            if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
                header('Content-Type: application/json');
                if (isset($operation_success)) {
                    echo json_encode(['success' => true, 'message' => $operation_success]);
                } else {
                    echo json_encode(['success' => false, 'message' => $operation_error ?? 'Unknown error']);
                }
                exit;
            }
        }
    }
}

// Start session for authentication
if ($auth_enabled) {
    // Session already started and configured above
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    // Regenerate session ID on login to prevent session fixation
    if (isset($_POST['login']) || (isset($_SESSION['user']) && !isset($_SESSION['regenerated']))) {
        session_regenerate_id(true);
        $_SESSION['regenerated'] = true;
    }
    
    // Initialize database
    $pdo = initDatabase($auth_db_path);
    if (!$pdo) {
        die('Authentication system unavailable');
    }
    
    // Handle login
    if (isset($_POST['login'])) {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember_me = isset($_POST['remember_me']);
        $csrf_token = $_POST['csrf_token'] ?? '';
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // Basic input validation
        if (empty($username) || empty($password)) {
            $login_error = "Username and password are required.";
        } elseif (!validateUsername($username)) {
            $login_error = "Invalid username format.";
        }
        
        // Validate CSRF token
        if (!validateCSRFToken($csrf_token)) {
            $login_error = "Invalid request. Please try again.";
        }
        // Check login attempts
        elseif (!checkLoginAttempts($pdo, $ip_address, $login_attempts_limit, $lockout_duration)) {
            $login_error = "Too many failed attempts. Please try again later.";
        } else {
            $user = authenticateUser($pdo, $username, $password);
            if ($user) {
                $_SESSION['user'] = $user;
                $_SESSION['login_time'] = time();
                logLoginAttempt($pdo, $ip_address, $username, true);
                
                // Handle remember me with secure token storage
                if ($remember_me) {
                    $token = generateRememberToken();
                    if (storeRememberToken($pdo, $user['id'], $token)) {
                        setcookie('remember_token', $token, time() + $remember_me_duration, '/', '', 
                                isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on', true);
                    }
                }
                
                // Clean up expired tokens
                cleanupExpiredTokens($pdo);
                
                header('Location: ' . basename($_SERVER['SCRIPT_NAME']));
                exit;
            } else {
                logLoginAttempt($pdo, $ip_address, $username, false);
                $login_error = "Invalid username or password";
            }
        }
    }
    
    // Handle logout
    if (isset($_GET['logout'])) {
        // Remove remember token from database if exists
        if (isset($_COOKIE['remember_token']) && isset($current_user)) {
            $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?");
            $stmt->execute([$current_user['id']]);
        }
        
        session_destroy();
        setcookie('remember_token', '', time() - 3600, '/');
        header('Location: ' . basename($_SERVER['SCRIPT_NAME']));
        exit;
    }
    
    // Check if user is authenticated or has valid remember token
    $current_user = $_SESSION['user'] ?? null;
    
    // If not authenticated but has remember token, try to authenticate
    if (!$current_user && isset($_COOKIE['remember_token'])) {
        $user_id = validateRememberToken($pdo, $_COOKIE['remember_token']);
        if ($user_id) {
            $stmt = $pdo->prepare("SELECT id, username, role FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                $_SESSION['user'] = $user;
                $_SESSION['login_time'] = time();
                $current_user = $user;
            }
        } else {
            // Invalid token, remove cookie
            setcookie('remember_token', '', time() - 3600, '/');
        }
    }
    
    // If not authenticated, show login form
    if (!$current_user) {
        showLoginForm($login_error ?? '');
        exit;
    }
    
    // Handle admin actions with input validation
    if ($current_user['role'] === 'admin' && isset($_GET['admin'])) {
        $admin_action = sanitizePath($_GET['admin']); // Reuse path sanitization for admin actions
        if (in_array($admin_action, ['users', 'add_user', 'edit_user', 'delete_user', 'logs'])) {
            handleAdminActions($pdo, $admin_action);
        } else {
            header('Location: ' . basename($_SERVER['SCRIPT_NAME']));
        }
        exit;
    }
}

function showLoginForm($error = '') {
    global $default_theme;
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - BetterIndex</title>
        <style>
            <?php echo generateThemeCSS($default_theme); ?>
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--text-primary);
            }
            
            .login-container {
                background: var(--bg-primary);
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
            }
            
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .login-header h1 {
                color: var(--accent-color);
                font-size: 2rem;
                margin-bottom: 8px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-primary);
            }
            
            .form-group input {
                width: 100%;
                padding: 12px;
                border: 2px solid var(--border-color);
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s ease;
            }
            
            .form-group input:focus {
                outline: none;
                border-color: var(--accent-color);
            }
            
            .checkbox-group {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 20px;
            }
            
            .login-btn {
                width: 100%;
                background: var(--accent-color);
                color: white;
                border: none;
                padding: 12px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 500;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }
            
            .login-btn:hover {
                background: var(--accent-hover);
            }
            
            .error-message {
                background: var(--danger-color);
                color: white;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🔐 <?php print $header_title; ?></h1>
                <p>Please log in to continue</p>
            </div>
            
            <?php if ($error): ?>
                <div class="error-message"><?php echo sanitizeOutput($error); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" id="remember_me" name="remember_me">
                    <label for="remember_me">Remember me for 30 days</label>
                </div>
                
                <button type="submit" name="login" class="login-btn">Log In</button>
            </form>
        </div>
    </body>
    </html>
    <?php
}

function handleAdminActions($pdo, $action) {
    switch ($action) {
        case 'users':
            showUserManagement($pdo);
            break;
        case 'add_user':
            if ($_POST) {
                addUser($pdo, $_POST);
            } else {
                showAddUserForm();
            }
            break;
        case 'edit_user':
            if ($_POST) {
                editUser($pdo, $_POST);
            } else {
                showEditUserForm($pdo, $_GET['id'] ?? 0);
            }
            break;
        case 'delete_user':
            deleteUser($pdo, $_GET['id'] ?? 0);
            break;
        case 'logs':
            showActivityLogs();
            break;
        default:
            header('Location: ' . basename($_SERVER['SCRIPT_NAME']));
            break;
    }
}

function showUserManagement($pdo) {
    $users = $pdo->query("SELECT * FROM users ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
    ?>
    <!DOCTYPE html>
    <html lang="en">
        <title>User Management - BetterIndex</title>
        <style>
            <?php echo generateThemeCSS($default_theme); ?>
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
            }
            
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            
            .header {
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 24px;
                margin-bottom: 24px;
                box-shadow: var(--shadow);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 16px;
            }
            
            .header h1 {
                font-size: 2rem;
                font-weight: 700;
                color: var(--accent-color);
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .btn {
                background: var(--accent-color);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
            
            .btn:hover { background: var(--accent-hover); }
            .btn-success { background: var(--success-color); }
            .btn-danger { background: var(--danger-color); }
            .btn-secondary { background: var(--text-secondary); }
            
            .table-container {
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 24px;
                box-shadow: var(--shadow);
                overflow-x: auto;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 16px;
            }
            
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
            }
            
            th {
                background: var(--bg-tertiary);
                font-weight: 600;
                color: var(--text-primary);
            }
            
            .role-badge {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 500;
                text-transform: uppercase;
            }
            
            .role-admin { background: var(--danger-color); color: white; }
            .role-guest { background: var(--text-secondary); color: white; }
            
            .actions {
                display: flex;
                gap: 8px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>👥 User Management</h1>
                <div>
                    <a href="?admin=add_user" class="btn btn-success">➕ Add User</a>
                    <a href="?admin=logs" class="btn btn-secondary">📋 View Logs</a>
                    <a href="?" class="btn">🏠 Back to Files</a>
                </div>
            </div>
            
            <div class="table-container">
                <h3>Users</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo sanitizeOutput($user['username']); ?></td>
                            <td>
                                <span class="role-badge role-<?php echo sanitizeOutput($user['role']); ?>">
                                    <?php echo sanitizeOutput($user['role']); ?>
                                </span>
                            </td>
                            <td><?php echo date('M j, Y', strtotime($user['created_at'])); ?></td>
                            <td class="actions">
                                <a href="?admin=edit_user&id=<?php echo intval($user['id']); ?>" class="btn">✏️ Edit</a>
                                <?php if ($user['username'] !== 'admin'): ?>
                                <a href="?admin=delete_user&id=<?php echo intval($user['id']); ?>" 
                                   class="btn btn-danger" 
                                   onclick="return confirm('Delete user <?php echo sanitizeOutput($user['username']); ?>?')">
                                   🗑️ Delete
                                </a>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showAddUserForm($error = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Add User - BetterIndex</title>
        <style>
            <?php echo generateThemeCSS($default_theme); ?>
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
                padding: 20px;
            }
            
            .container { max-width: 600px; margin: 0 auto; }
            
            .form-container {
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 32px;
                box-shadow: var(--shadow);
            }
            
            .form-header {
                text-align: center;
                margin-bottom: 32px;
            }
            
            .form-header h1 {
                color: var(--accent-color);
                font-size: 2rem;
                margin-bottom: 8px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-primary);
            }
            
            .form-group input, .form-group select {
                width: 100%;
                padding: 12px;
                border: 2px solid var(--border-color);
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s ease;
            }
            
            .form-group input:focus, .form-group select:focus {
                outline: none;
                border-color: var(--accent-color);
            }
            
            .btn {
                background: var(--accent-color);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 500;
                cursor: pointer;
                transition: background-color 0.3s ease;
                text-decoration: none;
                display: inline-block;
                margin-right: 12px;
            }
            
            .btn:hover { background: var(--accent-hover); }
            .btn-secondary { background: var(--text-secondary); }
            
            .error-message {
                background: var(--danger-color);
                color: white;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="form-container">
                <div class="form-header">
                    <h1>➕ Add New User</h1>
                </div>
                
                <?php if ($error): ?>
                    <div class="error-message"><?php echo sanitizeOutput($error); ?></div>
                <?php endif; ?>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="role">Role</label>
                        <select id="role" name="role" required>
                            <option value="guest">Guest</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn">Create User</button>
                    <a href="?admin=users" class="btn btn-secondary">Cancel</a>
                </form>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function addUser($pdo, $data) {
    // Validate input data
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';
    $role = $data['role'] ?? '';
    
    if (!validateUsername($username)) {
        showAddUserForm('Username must be 3-50 characters, alphanumeric, underscore, or hyphen only.');
        return;
    }
    
    if (!validatePassword($password)) {
        showAddUserForm('Password must be at least 8 characters long.');
        return;
    }
    
    if (!validateRole($role)) {
        showAddUserForm('Invalid role selected.');
        return;
    }
    
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)");
        $stmt->execute([
            $username,
            password_hash($password, PASSWORD_DEFAULT),
            $role
        ]);
        header('Location: ?admin=users');
    } catch (PDOException $e) {
        error_log("BetterIndex Add User Error: " . $e->getMessage());
        if (strpos($e->getMessage(), 'UNIQUE constraint failed') !== false) {
            showAddUserForm('Username already exists.');
        } else {
            showAddUserForm('Database error occurred. Please try again.');
        }
    }
}

function deleteUser($pdo, $user_id) {
    if (!validateUserId($user_id)) {
        header('Location: ?admin=users');
        return;
    }
    
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND username != 'admin'");
    $stmt->execute([intval($user_id)]);
    header('Location: ?admin=users');
}

function showActivityLogs() {
    global $log_file_path;
    
    $logs = [];
    if (file_exists($log_file_path)) {
        $logs = file($log_file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $logs = array_reverse($logs); // Show newest first
        $logs = array_slice($logs, 0, 100); // Show last 100 entries
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Activity Logs - BetterIndex</title>
        <style>
            <?php echo generateThemeCSS($default_theme); ?>
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
            }
            
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            
            .header {
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 24px;
                margin-bottom: 24px;
                box-shadow: var(--shadow);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 16px;
            }
            
            .header h1 {
                font-size: 2rem;
                font-weight: 700;
                color: var(--accent-color);
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .btn {
                background: var(--accent-color);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
            
            .btn:hover { background: var(--accent-hover); }
            
            .logs-container {
                background: var(--bg-secondary);
                border-radius: 12px;
                padding: 24px;
                box-shadow: var(--shadow);
            }
            
            .log-entry {
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 12px 16px;
                margin-bottom: 8px;
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                font-size: 14px;
                word-break: break-all;
            }
            
            .log-entry:hover {
                background: var(--bg-tertiary);
            }
            
            .no-logs {
                text-align: center;
                color: var(--text-secondary);
                padding: 40px;
                font-style: italic;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📋 Activity Logs</h1>
                <div>
                    <a href="?admin=users" class="btn">👥 Users</a>
                    <a href="?" class="btn">🏠 Back to Files</a>
                </div>
            </div>
            
            <div class="logs-container">
                <h3>Recent Activity (Last 100 entries)</h3>
                <?php if (empty($logs)): ?>
                    <div class="no-logs">
                        No file activity logged yet.
                    </div>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                        <div class="log-entry"><?php echo sanitizeOutput($log); ?></div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showFileViewer($file_path, $relative_path, $file_ext) {
    global $default_theme;
    $file_name = basename($file_path);
    $file_size = filesize($file_path);
    
    // Define viewable file types
    $image_types = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'];
    $text_types = ['txt', 'csv', 'json', 'xml', 'html', 'css', 'js', 'php', 'md', 'log'];
    $audio_types = ['mp3', 'wav', 'ogg', 'm4a'];
    $video_types = ['mp4', 'webm', 'ogg', 'mov'];
    $pdf_types = ['pdf'];
    
    $is_image = in_array($file_ext, $image_types);
    $is_text = in_array($file_ext, $text_types);
    $is_audio = in_array($file_ext, $audio_types);
    $is_video = in_array($file_ext, $video_types);
    $is_pdf = in_array($file_ext, $pdf_types);
    
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?php echo sanitizeOutput($file_name); ?> - BetterIndex</title>
        <style>
            <?php echo generateThemeCSS($default_theme); ?>
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
            }
            
            .viewer-header {
                background: var(--bg-secondary);
                border-bottom: 1px solid var(--border-color);
                padding: 16px 24px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 16px;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            
            .file-info h1 {
                font-size: 1.5rem;
                color: var(--accent-color);
                margin-bottom: 4px;
                word-break: break-word;
            }
            
            .file-meta {
                font-size: 14px;
                color: var(--text-secondary);
            }
            
            .viewer-actions {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }
            
            .btn {
                background: var(--accent-color);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
            
            .btn:hover { background: var(--accent-hover); }
            .btn-secondary { 
                background: var(--text-secondary); 
            }
            .btn-secondary:hover { 
                background: var(--text-muted); 
            }
            
            .viewer-content {
                padding: 24px;
                max-width: 100%;
                overflow: auto;
            }
            
            .image-viewer {
                text-align: center;
            }
            
            .image-viewer img {
                max-width: 100%;
                max-height: 80vh;
                border-radius: 8px;
                box-shadow: var(--shadow-lg);
            }
            
            .text-viewer {
                background: var(--bg-secondary);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 20px;
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                font-size: 14px;
                line-height: 1.5;
                white-space: pre-wrap;
                word-wrap: break-word;
                max-height: 80vh;
                overflow: auto;
            }
            
            /* Markdown styling */
            .text-viewer h1, .text-viewer h2, .text-viewer h3 {
                color: var(--accent-color);
                margin: 16px 0 8px 0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .text-viewer p {
                margin: 8px 0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
            }
            
            .text-viewer ul {
                margin: 8px 0;
                padding-left: 20px;
            }
            
            .text-viewer code {
                background: var(--bg-tertiary);
                padding: 2px 4px;
                border-radius: 3px;
                font-size: 13px;
            }
            
            .text-viewer pre {
                background: var(--bg-tertiary);
                padding: 12px;
                border-radius: 6px;
                overflow-x: auto;
                margin: 8px 0;
            }
            
            .text-viewer a {
                color: var(--accent-color);
                text-decoration: none;
            }
            
            .text-viewer a:hover {
                text-decoration: underline;
            }
            
            /* Syntax highlighting */
            .json-key { color: #0451a5; font-weight: bold; }
            .json-string { color: #0a8043; }
            .json-number { color: #098658; }
            .json-literal { color: #0000ff; }
            
            .xml-tag { color: #800000; }
            .xml-comment { color: #008000; font-style: italic; }
            
            .css-property { color: #ff0000; }
            .css-selector { color: #800080; font-weight: bold; }
            .css-comment { color: #008000; font-style: italic; }
            
            .js-keyword { color: #0000ff; font-weight: bold; }
            .js-string { color: #a31515; }
            .js-comment { color: #008000; font-style: italic; }
            
            .php-keyword { color: #0000ff; font-weight: bold; }
            .php-variable { color: #800080; }
            .php-string { color: #a31515; }
            .php-comment { color: #008000; font-style: italic; }
            .php-tag { color: #800000; font-weight: bold; }
            
            .media-viewer {
                text-align: center;
            }
            
            .media-viewer audio,
            .media-viewer video {
                max-width: 100%;
                border-radius: 8px;
                box-shadow: var(--shadow);
            }
            
            .pdf-viewer {
                text-align: center;
            }
            
            .pdf-viewer iframe {
                width: 100%;
                height: 80vh;
                border: 1px solid var(--border-color);
                border-radius: 8px;
            }
            
            .unsupported {
                text-align: center;
                padding: 60px 20px;
                color: var(--text-secondary);
            }
            
            .unsupported-icon {
                font-size: 4rem;
                margin-bottom: 16px;
                opacity: 0.5;
            }
            
            @media (max-width: 768px) {
                .viewer-header {
                    padding: 12px 16px;
                }
                
                .file-info h1 {
                    font-size: 1.25rem;
                }
                
                .viewer-content {
                    padding: 16px;
                }
                
                .viewer-actions {
                    width: 100%;
                    justify-content: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="viewer-header">
            <div class="file-info">
                <h1><?php echo sanitizeOutput($file_name); ?></h1>
                <div class="file-meta">
                    <?php echo sanitizeOutput(strtoupper($file_ext)); ?> • <?php echo formatFileSize($file_size); ?>
                </div>
            </div>
            <div class="viewer-actions">
                <a href="?download=<?php echo urlencode($relative_path); ?>" class="btn">⬇️ Download</a>
                <?php 
                // Get the directory path from the file path for proper back navigation
                $dir_path = dirname($relative_path);
                $back_url = ($dir_path === '.' || $dir_path === '') ? '?' : '?dir=' . urlencode($dir_path);
                ?>
                <a href="<?php echo $back_url; ?>" class="btn btn-secondary">← Back</a>
            </div>
        </div>
        
        <div class="viewer-content">
            <?php if ($is_image && $file_size < 10 * 1024 * 1024): // Limit images to 10MB ?>
                <div class="image-viewer">
                    <?php
                    // Stream image data more efficiently for large files
                    if ($file_size < 2 * 1024 * 1024) { // < 2MB, use data URI
                        echo '<img src="data:' . getMimeType($file_ext) . ';base64,' . base64_encode(file_get_contents($file_path)) . '" alt="' . sanitizeOutput($file_name) . '">';
                    } else { // >= 2MB, serve via separate request
                        echo '<img src="?download=' . urlencode($_GET['view']) . '&inline=1" alt="' . sanitizeOutput($file_name) . '">';
                    }
                    ?>
                </div>
            <?php elseif ($is_text && $file_size < 1024 * 1024): // Limit text files to 1MB ?>
                <div class="text-viewer">
                    <?php 
                    $content = file_get_contents($file_path);
                    if ($file_ext === 'md') {
                        echo parseMarkdown($content);
                    } elseif (in_array($file_ext, ['json', 'xml', 'html', 'css', 'js', 'php'])) {
                        echo '<pre><code class="language-' . $file_ext . '">' . syntaxHighlight($content, $file_ext) . '</code></pre>';
                    } else {
                        echo '<pre>' . sanitizeOutput($content) . '</pre>';
                    }
                    ?>
                </div>
            <?php elseif ($is_audio && $file_size < 20 * 1024 * 1024): // Limit audio to 20MB ?>
                <div class="media-viewer">
                    <audio controls>
                        <source src="?download=<?php echo urlencode($_GET['view']); ?>&inline=1" 
                                type="<?php echo getMimeType($file_ext); ?>">
                        Your browser does not support the audio element.
                    </audio>
                </div>
            <?php elseif ($is_video && $file_size < 50 * 1024 * 1024): // Limit videos to 50MB ?>
                <div class="media-viewer">
                    <video controls>
                        <source src="?download=<?php echo urlencode($_GET['view']); ?>&inline=1" 
                                type="<?php echo getMimeType($file_ext); ?>">
                        Your browser does not support the video element.
                    </video>
                </div>
            <?php elseif ($is_pdf && $file_size < 20 * 1024 * 1024): // Limit PDFs to 20MB ?>
                <div class="pdf-viewer">
                    <iframe src="?download=<?php echo urlencode($_GET['view']); ?>&inline=1"></iframe>
                </div>
            <?php else: ?>
                <div class="unsupported">
                    <div class="unsupported-icon">📄</div>
                    <h3>Preview not available</h3>
                    <p>This file type cannot be previewed inline<?php echo $file_size > 50 * 1024 * 1024 ? ' (file too large)' : ''; ?>.</p>
                    <p>Use the download button to save the file to your device.</p>
                </div>
            <?php endif; ?>
        </div>
    </body>
    </html>
    <?php
}

function getMimeType($extension) {
    $mime_types = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'bmp' => 'image/bmp',
        'webp' => 'image/webp',
        'svg' => 'image/svg+xml',
        'mp3' => 'audio/mpeg',
        'wav' => 'audio/wav',
        'ogg' => 'audio/ogg',
        'm4a' => 'audio/mp4',
        'mp4' => 'video/mp4',
        'webm' => 'video/webm',
        'mov' => 'video/quicktime',
        'pdf' => 'application/pdf'
    ];
    
    return $mime_types[$extension] ?? 'application/octet-stream';
}

function isPreviewable($extension) {
    $previewable_types = [
        // Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg',
        // Text files
        'txt', 'csv', 'json', 'xml', 'html', 'css', 'js', 'php', 'md', 'log',
        // Audio
        'mp3', 'wav', 'ogg', 'm4a',
        // Video
        'mp4', 'webm', 'mov',
        // Documents
        'pdf'
    ];
    
    return in_array(strtolower($extension), $previewable_types);
}

// Basic markdown parser
function parseMarkdown($text) {
    // First, extract and preserve code blocks to prevent parsing inside them
    $code_blocks = [];
    $code_counter = 0;
    
    // Extract triple backtick code blocks
    $text = preg_replace_callback('/```(.*?)```/s', function($matches) use (&$code_blocks, &$code_counter) {
        $placeholder = "___CODE_BLOCK_{$code_counter}___";
        $code_blocks[$placeholder] = '<pre><code>' . htmlspecialchars($matches[1]) . '</code></pre>';
        $code_counter++;
        return $placeholder;
    }, $text);
    
    // Extract inline code
    $text = preg_replace_callback('/`([^`]+)`/', function($matches) use (&$code_blocks, &$code_counter) {
        $placeholder = "___INLINE_CODE_{$code_counter}___";
        $code_blocks[$placeholder] = '<code>' . htmlspecialchars($matches[1]) . '</code>';
        $code_counter++;
        return $placeholder;
    }, $text);
    
    // Now apply markdown parsing to the remaining text
    // Headers
    $text = preg_replace('/^### (.*$)/m', '<h3>$1</h3>', $text);
    $text = preg_replace('/^## (.*$)/m', '<h2>$1</h2>', $text);
    $text = preg_replace('/^# (.*$)/m', '<h1>$1</h1>', $text);
    
    // Bold and italic
    $text = preg_replace('/\*\*(.*?)\*\*/', '<strong>$1</strong>', $text);
    $text = preg_replace('/\*(.*?)\*/', '<em>$1</em>', $text);
    
    // Links
    $text = preg_replace('/\[([^\]]+)\]\(([^)]+)\)/', '<a href="$2" target="_blank">$1</a>', $text);
    
    // Lists
    $text = preg_replace('/^\* (.*)$/m', '<li>$1</li>', $text);
    $text = preg_replace('/(<li>.*<\/li>)/s', '<ul>$1</ul>', $text);
    
    // Line breaks
    $text = preg_replace('/\n\n/', '</p><p>', $text);
    $text = '<p>' . $text . '</p>';
    
    // Restore code blocks
    foreach ($code_blocks as $placeholder => $code) {
        $text = str_replace($placeholder, $code, $text);
    }
    
    return $text;
}

// Syntax highlighter for code files
function syntaxHighlight($code, $language) {
    $code = htmlspecialchars($code);
    
    switch (strtolower($language)) {
        case 'json':
            // Highlight JSON
            $code = preg_replace('/"([^"]+)"\s*:/', '<span class="json-key">"$1"</span>:', $code);
            $code = preg_replace('/:\s*"([^"]*)"/', ': <span class="json-string">"$1"</span>', $code);
            $code = preg_replace('/:\s*(true|false|null)/', ': <span class="json-literal">$1</span>', $code);
            $code = preg_replace('/:\s*(-?\d+\.?\d*)/', ': <span class="json-number">$1</span>', $code);
            break;
            
        case 'xml':
        case 'html':
            // Highlight XML/HTML
            $code = preg_replace('/(&lt;\/?[^&gt;]+&gt;)/', '<span class="xml-tag">$1</span>', $code);
            $code = preg_replace('/(&lt;!--.*?--&gt;)/s', '<span class="xml-comment">$1</span>', $code);
            break;
            
        case 'css':
            // Highlight CSS
            $code = preg_replace('/([a-zA-Z-]+)\s*:/', '<span class="css-property">$1</span>:', $code);
            $code = preg_replace('/([.#][a-zA-Z0-9_-]+)/', '<span class="css-selector">$1</span>', $code);
            $code = preg_replace('/(\/\*.*?\*\/)/s', '<span class="css-comment">$1</span>', $code);
            break;
            
        case 'js':
        case 'javascript':
            // Highlight JavaScript
            $keywords = 'function|var|let|const|if|else|for|while|return|true|false|null|undefined';
            $code = preg_replace('/\b(' . $keywords . ')\b/', '<span class="js-keyword">$1</span>', $code);
            $code = preg_replace('/(\/\/.*$)/m', '<span class="js-comment">$1</span>', $code);
            $code = preg_replace('/(\/\*.*?\*\/)/s', '<span class="js-comment">$1</span>', $code);
            $code = preg_replace('/"([^"]*)"/', '<span class="js-string">"$1"</span>', $code);
            $code = preg_replace("/'([^']*)'/", '<span class="js-string">\'$1\'</span>', $code);
            break;
            
        case 'php':
            // Highlight PHP
            $keywords = 'function|class|public|private|protected|static|if|else|elseif|for|foreach|while|return|true|false|null|array|echo|print|var|global';
            $code = preg_replace('/\b(' . $keywords . ')\b/', '<span class="php-keyword">$1</span>', $code);
            $code = preg_replace('/(\$[a-zA-Z_][a-zA-Z0-9_]*)/', '<span class="php-variable">$1</span>', $code);
            $code = preg_replace('/(\/\/.*$)/m', '<span class="php-comment">$1</span>', $code);
            $code = preg_replace('/(\/\*.*?\*\/)/s', '<span class="php-comment">$1</span>', $code);
            $code = preg_replace('/"([^"]*)"/', '<span class="php-string">"$1"</span>', $code);
            $code = preg_replace("/'([^']*)'/", '<span class="php-string">\'$1\'</span>', $code);
            $code = preg_replace('/(&lt;\?php|&lt;\?|\?&gt;)/', '<span class="php-tag">$1</span>', $code);
            break;
    }
    
    return $code;
}

// Handle file viewing
if (isset($_GET['view']) && !empty($_GET['view'])) {
    $file_path = validatePath($_GET['view'], $base_path);
    
    // Security check: ensure file is within base path and exists
    if ($file_path && is_file($file_path)) {
        $file_ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $extension_allowed = in_array('*', $allowed_extensions) || in_array($file_ext, $allowed_extensions);
        
        if ($extension_allowed) {
            // Log view activity if enabled
            if ($log_activity) {
                $current_user = $auth_enabled ? ($_SESSION['user'] ?? null) : null;
                $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                logActivity($log_file_path, 'VIEW', $_GET['view'], $current_user, $ip_address);
            }
            
            showFileViewer($file_path, $_GET['view'], $file_ext);
            exit;
        }
    }
    
    header('HTTP/1.0 404 Not Found');
    exit('File not found or access denied');
}

// Handle file download
if (isset($_GET['download']) && !empty($_GET['download'])) {
    $file_path = validatePath($_GET['download'], $base_path);
    
    // Security check: ensure file is within base path and exists
    if ($file_path && is_file($file_path)) {
        $file_size = filesize($file_path);
        $file_ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Check if extension is allowed and file size is within limit
        $extension_allowed = in_array('*', $allowed_extensions) || in_array($file_ext, $allowed_extensions);
        if ($extension_allowed && $file_size <= $max_file_size) {
            // Log download activity if enabled
            if ($log_activity) {
                $current_user = $auth_enabled ? ($_SESSION['user'] ?? null) : null;
                $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                logActivity($log_file_path, 'DOWNLOAD', $_GET['download'], $current_user, $ip_address);
            }
            
            // Handle inline viewing for media files
            if (isset($_GET['inline']) && $_GET['inline'] === '1') {
                $mime_type = getMimeType($file_ext);
                header('Content-Type: ' . $mime_type);
                header('Content-Length: ' . $file_size);
                header('Cache-Control: public, max-age=3600'); // Cache for 1 hour
            } else {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
                header('Content-Length: ' . $file_size);
                header('Cache-Control: no-cache, must-revalidate');
                header('Pragma: no-cache');
            }
            
            // Stream large files in chunks to avoid memory issues
            if ($file_size > 10 * 1024 * 1024) { // Files > 10MB
                $handle = fopen($file_path, 'rb');
                if ($handle) {
                    while (!feof($handle)) {
                        echo fread($handle, 8192); // 8KB chunks
                        flush();
                    }
                    fclose($handle);
                }
            } else {
                readfile($file_path);
            }
            exit;
        }
    }
    
    // If we reach here, download failed
    header('HTTP/1.0 404 Not Found');
    exit('File not found or access denied');
}

// Get current directory with security validation
$current_dir = isset($_GET['dir']) ? sanitizePath($_GET['dir']) : '';
$current_path = $current_dir ? validatePath($current_dir, $base_path) : $base_path;

// Security check: ensure we're within base path
if (!$current_path || !is_dir($current_path)) {
    $current_path = $base_path;
    $current_dir = '';
}

// Get directory contents
function getDirectoryContents($path, $base_path, $hide_dotfiles = true) {
    global $allowed_extensions;
    $items = [];
    
    if (!is_dir($path)) {
        return $items;
    }
    
    $files = scandir($path);
    
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') continue;
        
        // Hide this script file only in its own directory
        if ($path === $base_path && $file === basename(__FILE__)) continue;
        
        // Hide dotfiles if configured
        if ($hide_dotfiles && $file[0] === '.') continue;
        
        $full_path = $path . '/' . $file;
        $relative_path = str_replace($base_path . '/', '', $full_path);
        
        // For files, check if extension is allowed
        if (is_file($full_path)) {
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            // Skip files with disallowed extensions (unless wildcard is set)
            if (!in_array('*', $allowed_extensions) && !in_array($extension, $allowed_extensions)) {
                continue;
            }
        }
        
        $item = [
            'name' => $file,
            'path' => $relative_path,
            'is_dir' => is_dir($full_path),
            'size' => is_file($full_path) ? filesize($full_path) : 0,
            'modified' => filemtime($full_path),
            'extension' => is_file($full_path) ? strtolower(pathinfo($file, PATHINFO_EXTENSION)) : ''
        ];
        
        $items[] = $item;
    }
    
    // Sort: directories first, then files alphabetically
    usort($items, function($a, $b) {
        if ($a['is_dir'] && !$b['is_dir']) return -1;
        if (!$a['is_dir'] && $b['is_dir']) return 1;
        return strcasecmp($a['name'], $b['name']);
    });
    
    return $items;
}

function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' B';
    }
}

function getFileIcon($extension, $is_dir) {
    if ($is_dir) return '📁';
    
    $icons = [
        'pdf' => '📄',
        'doc' => '📝', 'docx' => '📝',
        'xls' => '📊', 'xlsx' => '📊',
        'ppt' => '📽️', 'pptx' => '📽️',
        'zip' => '🗜️', 'rar' => '🗜️', '7z' => '🗜️', 'tar' => '🗜️', 'gz' => '🗜️',
        'jpg' => '🖼️', 'jpeg' => '🖼️', 'png' => '🖼️', 'gif' => '🖼️', 'bmp' => '🖼️', 'svg' => '🖼️',
        'mp3' => '🎵', 'wav' => '🎵', 'flac' => '🎵',
        'mp4' => '🎬', 'avi' => '🎬', 'mov' => '🎬', 'wmv' => '🎬', 'flv' => '🎬',
        'html' => '🌐', 'css' => '🎨', 'js' => '⚡', 'php' => '🐘',
        'txt' => '📄', 'json' => '📋', 'xml' => '📋',
        'tbn' => '📦'
    ];
    
    return isset($icons[$extension]) ? $icons[$extension] : '📄';
}

$items = getDirectoryContents($current_path, $base_path, $hide_dotfiles);
$breadcrumbs = [];

if ($current_dir) {
    $parts = explode('/', $current_dir);
    $path = '';
    foreach ($parts as $part) {
        $path .= ($path ? '/' : '') . $part;
        $breadcrumbs[] = ['name' => $part, 'path' => $path];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?> - BetterIndex</title>
    <style>
        <?php echo generateThemeCSS($default_theme); ?>

        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #404040;
            --text-primary: #ffffff;
            --text-secondary: #b3b3b3;
            --text-muted: #666666;
            --border-color: #404040;
            --accent-color: #4dabf7;
            --accent-hover: #339af0;
            --success-color: #51cf66;
            --warning-color: #ffd43b;
            --danger-color: #ff6b6b;
            --shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 0.5rem 1rem rgba(0, 0, 0, 0.4);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: all 0.3s ease;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .user-badge {
            background: var(--bg-tertiary);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-color);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .control-btn {
            background: var(--bg-tertiary);
            border: 2px solid var(--border-color);
            border-radius: 50px;
            padding: 8px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .control-btn:hover {
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }

        .view-selector {
            position: relative;
        }

        .view-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            box-shadow: var(--shadow-lg);
            z-index: 1000;
            min-width: 150px;
            display: none;
        }

        .view-dropdown.show {
            display: block;
        }

        .admin-controls {
            position: relative;
        }

        .operations-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            box-shadow: var(--shadow-lg);
            min-width: 200px;
            z-index: 1000;
            display: none;
        }

        .operations-dropdown.show {
            display: block;
        }

        .operation-option {
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            transition: background-color 0.2s ease;
            border-bottom: 1px solid var(--border-color);
        }

        .operation-option:last-child {
            border-bottom: none;
        }

        .operation-option:hover {
            background: var(--bg-secondary);
        }

        .operation-option:first-child {
            border-radius: 10px 10px 0 0;
        }

        .operation-option:last-child {
            border-radius: 0 0 10px 10px;
        }

        /* File operation modals */
        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: var(--overlay);
            backdrop-filter: blur(4px);
        }

        .modal-content {
            background-color: var(--bg-primary);
            margin: 5% auto;
            padding: 30px;
            border: 2px solid var(--border-color);
            border-radius: 16px;
            width: 90%;
            max-width: 500px;
            box-shadow: var(--shadow-lg);
            position: relative;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--border-color);
        }

        .modal-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 4px;
            border-radius: 4px;
            transition: all 0.2s ease;
        }

        .close-btn:hover {
            background: var(--danger-color);
            color: white;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-primary);
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 1rem;
            transition: border-color 0.2s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        .file-upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 12px;
            padding: 40px 20px;
            text-align: center;
            background: var(--bg-secondary);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .file-upload-area:hover,
        .file-upload-area.dragover {
            border-color: var(--accent-color);
            background: var(--bg-tertiary);
        }

        .upload-icon {
            font-size: 3rem;
            margin-bottom: 16px;
            color: var(--text-secondary);
        }

        .upload-text {
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .upload-subtext {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 24px;
            padding-top: 20px;
            padding-right: 20px;
            padding-bottom: 20px;
            border-top: 2px solid var(--border-color);
        }

        .btn-primary {
            background: var(--accent-color);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        .btn-primary:hover {
            background: var(--accent-hover);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 2px solid var(--border-color);
            padding: 10px 24px;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-secondary:hover {
            background: var(--bg-secondary);
            border-color: var(--accent-color);
        }

        #trashContents {
            padding-bottom: 10px;
        }

        .trash-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 8px;
            background: var(--bg-secondary);
        }

        .trash-item-info {
            flex: 1;
        }

        .trash-item-name {
            font-weight: 500;
            color: var(--text-primary);
        }

        .trash-item-meta {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .trash-actions {
            display: flex;
            gap: 8px;
        }

        .trash-header {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 20px;
            padding: 0 20px 16px 20px;
            border-bottom: 1px solid var(--border-color);
        }

        .trash-items-list {
            padding: 0 20px;
        }

        /* Notification styles */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            animation: slideIn 0.3s ease-out;
        }

        .notification-success {
            background: #28a745;
        }

        .notification-error {
            background: #dc3545;
        }

        .notification-info {
            background: var(--accent-color);
        }

        .notification-message {
            flex: 1;
        }

        .notification-close {
            background: none;
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            padding: 0;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .notification-close:hover {
            opacity: 0.7;
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
                transform: translateX(0);
            }
            to {
                opacity: 0;
                transform: translateX(-20px);
            }
        }

        .btn-small {
            padding: 6px 12px;
            font-size: 0.85rem;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-restore {
            background: var(--success-color);
            color: white;
        }

        .btn-restore:hover {
            background: var(--success-hover);
        }

        .btn-delete {
            background: var(--danger-color);
            color: white;
        }

        .btn-delete:hover {
            background: var(--danger-hover);
        }

        /* File item context menu for admin operations */
        .file-item.admin-mode {
            position: relative;
        }

        .file-item.admin-mode:hover .admin-actions {
            opacity: 1;
            visibility: visible;
        }

        .admin-actions {
            position: absolute;
            top: 8px;
            right: 8px;
            display: flex;
            gap: 4px;
            opacity: 0;
            visibility: hidden;
            transition: all 0.2s ease;
            z-index: 10;
        }

        .admin-action-btn {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 4px 8px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s ease;
        }

        .admin-action-btn:hover {
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }

        .admin-action-btn.delete:hover {
            background: var(--danger-color);
            border-color: var(--danger-color);
        }

        .view-option {
            padding: 12px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
            border-bottom: 1px solid var(--border-color);
        }

        .view-option:last-child {
            border-bottom: none;
        }

        .view-option:hover {
            background: var(--bg-tertiary);
        }

        .view-option.active {
            background: var(--accent-color);
            color: white;
        }

        .breadcrumb {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: space-between;
        }

        .breadcrumb-nav {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .breadcrumb a {
            color: var(--accent-color);
            text-decoration: none;
            font-weight: 500;
            padding: 4px 8px;
            border-radius: 4px;
            transition: all 0.2s ease;
        }

        .refresh-btn {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .refresh-btn:hover {
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }

        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 16px;
        }

        .file-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .file-compact {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 8px;
        }

        .file-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: visible;
        }

        .file-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
            border-color: var(--accent-color);
        }

        .file-item.directory {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
        }

        /* List view styles */
        .file-list .file-item {
            border-radius: 8px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .file-list .file-item:hover {
            transform: none;
            background: var(--bg-tertiary);
        }

        .file-list .file-header {
            margin-bottom: 0;
            flex: 1;
            min-width: 0;
        }

        .file-list .file-meta {
            margin-top: 0;
            display: flex;
            gap: 20px;
            align-items: center;
            flex-shrink: 0;
        }

        .file-list .download-btn,
        .file-list .view-btn {
            position: static;
            opacity: 1;
            margin-left: 8px;
        }

        /* Compact view styles */
        .file-compact .file-item {
            padding: 12px;
            border-radius: 8px;
        }

        .file-compact .file-item:hover {
            transform: translateY(-1px);
        }

        .file-compact .file-header {
            margin-bottom: 8px;
        }

        .file-compact .file-icon {
            font-size: 1.5rem;
        }

        .file-compact .file-name {
            font-size: 0.9rem;
        }

        .file-compact .file-meta {
            font-size: 0.75rem;
            margin-top: 4px;
        }

        .file-compact .download-btn,
        .file-compact .view-btn {
            width: 24px;
            height: 24px;
            font-size: 12px;
        }

        .file-compact .view-btn {
            right: 32px;
        }

        .file-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }

        .file-icon {
            font-size: 2rem;
            line-height: 1;
        }

        .file-name {
            font-weight: 600;
            font-size: 1.1rem;
            color: var(--text-primary);
            word-break: break-word;
            flex: 1;
        }

        .file-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 8px;
        }

        .file-size {
            font-weight: 500;
        }

        .file-date {
            font-style: italic;
        }

        .download-btn, .view-btn, .admin-btn {
            position: absolute;
            background: var(--accent-color);
            color: white;
            border: none;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            cursor: pointer;
            opacity: 0;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
        }

        .download-btn, .view-btn {
            top: 12px;
        }

        .view-btn {
            right: 52px;
            background: var(--success-color, #28a745);
            top: 12px;
        }

        .download-btn {
            right: 12px;
            top: 12px;
        }

        /* Admin dropdown menu */
        .admin-dropdown {
            position: relative;
            display: inline-block;
            margin-left: 8px;
        }

        .admin-dropdown-btn {
            background: var(--bg-tertiary, #f8f9fa);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 4px 8px;
            cursor: pointer;
            font-size: 12px;
            color: var(--text-secondary);
            transition: all 0.2s ease;
        }

        .admin-dropdown-btn:hover {
            background: var(--bg-secondary);
            border-color: var(--accent-color);
        }

        .admin-dropdown-content {
            display: none;
            position: absolute;
            right: 0;
            top: 100%;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 9999;
            min-width: 120px;
            margin-top: 2px;
        }

        .admin-dropdown.show .admin-dropdown-content {
            display: block;
        }

        .admin-dropdown-item {
            display: block;
            width: 100%;
            padding: 8px 12px;
            border: none;
            background: none;
            text-align: left;
            cursor: pointer;
            font-size: 13px;
            color: var(--text-primary);
            transition: background-color 0.2s ease;
        }

        .admin-dropdown-item:hover {
            background: var(--bg-secondary);
        }

        .admin-dropdown-item.view {
            color: var(--success-color, #28a745);
        }

        .admin-dropdown-item.download {
            color: var(--accent-color);
        }

        .admin-dropdown-item.rename {
            color: var(--info-color, #17a2b8);
        }

        .admin-dropdown-item.delete {
            color: var(--danger-color, #dc3545);
        }

        .admin-dropdown-item:first-child {
            border-radius: 6px 6px 0 0;
        }

        .admin-dropdown-item:last-child {
            border-radius: 0 0 6px 6px;
        }

        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }

        .modal-content {
            background-color: var(--bg-primary);
            margin: 15% auto;
            padding: 0;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.25rem;
        }

        .close {
            color: var(--text-secondary);
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            line-height: 1;
        }

        .close:hover {
            color: var(--text-primary);
        }

        .form-group {
            margin-bottom: 20px;
            padding: 0 24px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-primary);
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: border-color 0.3s ease;
            box-sizing: border-box;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        .form-actions {
            padding: 20px 24px;
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-primary {
            background: var(--accent-color);
            color: white;
        }

        .btn-primary:hover {
            background: var(--accent-hover, #0056b3);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--bg-quaternary);
        }

        .btn-danger {
            background: #dc3545;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        /* Upload modal specific styles */
        .file-upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 8px;
            padding: 40px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: var(--bg-secondary);
        }

        .file-upload-area:hover {
            border-color: var(--accent-color);
            background: var(--bg-tertiary);
        }

        .file-upload-area.dragover {
            border-color: var(--accent-color);
            background: var(--bg-tertiary);
        }

        .upload-icon {
            font-size: 3rem;
            margin-bottom: 16px;
            opacity: 0.7;
        }

        .upload-text {
            font-size: 1.1rem;
            color: var(--text-primary);
            margin-bottom: 8px;
        }

        .upload-subtext {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 16px;
        }

        .selected-filename {
            margin-top: 16px;
            font-weight: 500;
            color: var(--accent-color);
            min-height: 20px;
        }

        .file-item:hover .download-btn,
        .file-item:hover .view-btn {
            opacity: 1;
        }

        .download-btn:hover {
            background: var(--accent-hover);
            transform: scale(1.1);
        }

        .view-btn:hover {
            background: var(--success-hover, #218838);
            transform: scale(1.1);
        }

        .admin-btn:hover {
            transform: scale(1.1);
        }

        .admin-btn.delete-btn:hover {
            background: #c82333;
        }

        .admin-btn.rename-btn:hover {
            background: #138496;
        }

        .stats {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--shadow);
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
        }

        .stat-item {
            text-align: center;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-color);
            display: block;
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }

        .empty-state-icon {
            font-size: 4rem;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid var(--border-color);
            border-radius: 50%;
            border-top-color: var(--accent-color);
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }

            .header-controls {
                justify-content: center;
                width: 100%;
            }
            
            .file-grid {
                grid-template-columns: 1fr;
            }

            .file-compact {
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            }
            
            .stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header fade-in">
            <h1>
                <span>📁</span>
                <?php print $header_title; ?>
            </h1>
            <div class="header-controls">
                <div class="view-selector">
                    <button class="control-btn" onclick="toggleViewDropdown()">
                        <span id="view-icon">⊞</span>
                        <span id="view-text">Grid View</span>
                        <span>▼</span>
                    </button>
                    <div class="view-dropdown" id="viewDropdown">
                        <div class="view-option" data-view="grid" onclick="setView('grid')">
                            <span>⊞</span>
                            <span>Grid View</span>
                        </div>
                        <div class="view-option" data-view="list" onclick="setView('list')">
                            <span>☰</span>
                            <span>List View</span>
                        </div>
                        <div class="view-option" data-view="compact" onclick="setView('compact')">
                            <span>⊡</span>
                            <span>Compact View</span>
                        </div>
                    </div>
                </div>
                <?php if ($auth_enabled && isset($current_user)): ?>
                    <?php if ($current_user['role'] === 'admin'): ?>
                        <div class="admin-controls">
                            <button class="control-btn" onclick="toggleFileOperations()">
                                <span>⚙️</span>
                                <span>File Operations</span>
                                <span>▼</span>
                            </button>
                            <div class="operations-dropdown" id="operationsDropdown">
                                <div class="operation-option" onclick="showUploadDialog()">
                                    <span>📤</span>
                                    <span>Upload File</span>
                                </div>
                                <div class="operation-option" onclick="showCreateFolderDialog()">
                                    <span>📁</span>
                                    <span>Create Folder</span>
                                </div>
                                <div class="operation-option" onclick="showTrashDialog()">
                                    <span>🗑️</span>
                                    <span>View Trash</span>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                    <div class="user-info">
                        <span class="user-badge">
                            <?php echo $current_user['role'] === 'admin' ? '👑' : '👤'; ?>
                            <?php echo sanitizeOutput($current_user['username']); ?>
                        </span>
                        <?php if ($current_user['role'] === 'admin'): ?>
                            <a href="?admin=users" class="control-btn">⚙️ Admin</a>
                        <?php endif; ?>
                        <a href="?logout" class="control-btn">🚪 Logout</a>
                    </div>
                <?php endif; ?>
                <button class="control-btn" onclick="toggleTheme()">
                    <span id="theme-icon">🌙</span>
                    <span id="theme-text">Dark Mode</span>
                </button>
            </div>
        </header>

        <?php if ($current_dir || count($breadcrumbs) > 0): ?>
        <nav class="breadcrumb fade-in">
            <div class="breadcrumb-nav">
                <a href="?">🏠 Home</a>
                <?php foreach ($breadcrumbs as $crumb): ?>
                    <span class="breadcrumb-separator">›</span>
                    <a href="?dir=<?php echo urlencode($crumb['path']); ?>"><?php echo sanitizeOutput($crumb['name']); ?></a>
                <?php endforeach; ?>
            </div>
            <button class="refresh-btn" onclick="refreshPage()" title="Refresh">
                🔄 Refresh
            </button>
        </nav>
        <?php endif; ?>

        <?php if (empty($items)): ?>
        <div class="empty-state fade-in">
            <div class="empty-state-icon">📂</div>
            <h3>This directory is empty</h3>
            <p>No files or folders to display</p>
        </div>
        <?php else: ?>
        <div class="file-container fade-in" id="fileContainer">
        <div class="file-grid" id="fileGrid">
            <?php 
            $file_count = 0;
            $dir_count = 0;
            $total_size = 0;
            
            foreach ($items as $item): 
                if ($item['is_dir']) {
                    $dir_count++;
                } else {
                    $file_count++;
                    $total_size += $item['size'];
                }
            ?>
            <div class="file-item <?php echo $item['is_dir'] ? 'directory' : 'file'; ?><?php echo (!$item['is_dir'] && (in_array('*', $allowed_extensions) || in_array($item['extension'], $allowed_extensions)) && isPreviewable($item['extension'])) ? ' has-view' : ''; ?>" 
                 onclick="<?php echo $item['is_dir'] ? "window.location.href='?dir=" . urlencode($item['path']) . "'" : (!$item['is_dir'] && (in_array('*', $allowed_extensions) || in_array($item['extension'], $allowed_extensions)) && isPreviewable($item['extension']) ? "viewFile('" . addslashes($item['path']) . "')" : (!$item['is_dir'] && (in_array('*', $allowed_extensions) || in_array($item['extension'], $allowed_extensions)) ? "downloadFile('" . addslashes($item['path']) . "')" : '')); ?>">
                <div class="file-header">
                    <span class="file-icon"><?php echo getFileIcon($item['extension'], $item['is_dir']); ?></span>
                    <span class="file-name"><?php echo sanitizeOutput($item['name']); ?></span>
                </div>
                
                <div class="file-meta">
                    <span class="file-size">
                        <?php echo $item['is_dir'] ? 'Directory' : formatFileSize($item['size']); ?>
                    </span>
                    <span class="file-date">
                        <?php echo date('M j, Y g:i A', $item['modified']); ?>
                        <div class="admin-dropdown">
                            <button class="admin-dropdown-btn" onclick="event.stopPropagation(); toggleAdminDropdown(this)" title="File Actions">
                                ▼
                            </button>
                            <div class="admin-dropdown-content">
                                <?php if (!$item['is_dir'] && (in_array('*', $allowed_extensions) || in_array($item['extension'], $allowed_extensions))): ?>
                                    <?php if (isPreviewable($item['extension'])): ?>
                                    <button class="admin-dropdown-item view" onclick="event.stopPropagation(); viewFile('<?php echo addslashes($item['path']); ?>')">
                                        👁️ View
                                    </button>
                                    <?php endif; ?>
                                    <button class="admin-dropdown-item download" onclick="event.stopPropagation(); downloadFile('<?php echo addslashes($item['path']); ?>')">
                                        ⬇️ Download
                                    </button>
                                <?php endif; ?>
                                <?php if ($auth_enabled && isset($current_user) && $current_user['role'] === 'admin'): ?>
                                    <button class="admin-dropdown-item rename" onclick="event.stopPropagation(); showRenameModal('<?php echo addslashes($item['path']); ?>', '<?php echo addslashes($item['name']); ?>')">
                                        ✏️ Rename
                                    </button>
                                    <button class="admin-dropdown-item delete" onclick="event.stopPropagation(); confirmDelete('<?php echo addslashes($item['path']); ?>', '<?php echo addslashes($item['name']); ?>')">
                                        🗑️ Delete
                                    </button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </span>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        </div>

        <div class="stats fade-in">
            <div class="stat-item">
                <span class="stat-number"><?php echo $dir_count; ?></span>
                <span class="stat-label">Directories</span>
            </div>
            <div class="stat-item">
                <span class="stat-number"><?php echo $file_count; ?></span>
                <span class="stat-label">Files</span>
            </div>
            <div class="stat-item">
                <span class="stat-number"><?php echo formatFileSize($total_size); ?></span>
                <span class="stat-label">Total Size</span>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script>
        // Configuration from PHP
        const DEFAULT_THEME = '<?php echo $default_theme; ?>';
        const DEFAULT_VIEW = '<?php echo $default_view; ?>';

        // Theme management
        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || DEFAULT_THEME;
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeButton(savedTheme);
        }

        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeButton(newTheme);
        }

        function updateThemeButton(theme) {
            const icon = document.getElementById('theme-icon');
            const text = document.getElementById('theme-text');
            
            if (theme === 'dark') {
                icon.textContent = '☀️';
                text.textContent = 'Light Mode';
            } else {
                icon.textContent = '🌙';
                text.textContent = 'Dark Mode';
            }
        }

        // View functionality
        function viewFile(filePath) {
            const viewUrl = `?view=${encodeURIComponent(filePath)}`;
            window.open(viewUrl, '_blank');
        }

        // Download functionality
        function downloadFile(filePath) {
            const downloadUrl = `?download=${encodeURIComponent(filePath)}`;
            
            // Create a temporary link and trigger download
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' || e.keyCode === 27) {
                // Prevent default behavior and stop propagation
                e.preventDefault();
                e.stopPropagation();
                
                // Don't navigate if user is typing in an input field
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                    return;
                }
                
                // Go back to parent directory
                const currentUrl = new URL(window.location);
                const currentDir = currentUrl.searchParams.get('dir');
                
                if (currentDir) {
                    const parentDir = currentDir.split('/').slice(0, -1).join('/');
                    if (parentDir) {
                        window.location.href = `?dir=${encodeURIComponent(parentDir)}`;
                    } else {
                        window.location.href = '?';
                    }
                } else {
                    // Already at root, do nothing or provide feedback
                    console.log('Already at root directory');
                }
            }
        }, true); // Use capture phase for more reliable event handling

        // View management
        function initView() {
            const savedView = localStorage.getItem('view') || DEFAULT_VIEW;
            setView(savedView);
        }

        function setView(viewType) {
            const container = document.getElementById('fileGrid');
            const viewIcon = document.getElementById('view-icon');
            const viewText = document.getElementById('view-text');
            const dropdown = document.getElementById('viewDropdown');
            
            // Check if container exists before manipulating it
            if (!container) {
                console.warn('fileGrid container not found');
                return;
            }
            
            // Remove all view classes
            container.className = container.className.replace(/file-(grid|list|compact)/g, '');
            
            // Add new view class
            container.classList.add('file-' + viewType);
            
            // Update button text and icon
            const viewConfig = {
                'grid': { icon: '⊞', text: 'Grid View' },
                'list': { icon: '☰', text: 'List View' },
                'compact': { icon: '⊡', text: 'Compact View' }
            };
            
            if (viewIcon) viewIcon.textContent = viewConfig[viewType].icon;
            if (viewText) viewText.textContent = viewConfig[viewType].text;
            
            // Update active state in dropdown
            document.querySelectorAll('.view-option').forEach(option => {
                option.classList.remove('active');
                if (option.dataset.view === viewType) {
                    option.classList.add('active');
                }
            });
            
            // Save to localStorage
            localStorage.setItem('view', viewType);
            
            // Close dropdown
            dropdown.classList.remove('show');
        }

        function toggleViewDropdown() {
            const dropdown = document.getElementById('viewDropdown');
            dropdown.classList.toggle('show');
        }

        // Close dropdown when clicking outside
        document.addEventListener('click', function(event) {
            const viewSelector = document.querySelector('.view-selector');
            const dropdown = document.getElementById('viewDropdown');
            
            if (!viewSelector.contains(event.target)) {
                dropdown.classList.remove('show');
            }
        });

        // Initialize theme and view on page load
        document.addEventListener('DOMContentLoaded', function() {
            initTheme();
            initView();
        });

        // Add smooth scrolling
        document.documentElement.style.scrollBehavior = 'smooth';

        // Add loading states for navigation
        document.querySelectorAll('.file-item.directory').forEach(item => {
            item.addEventListener('click', function() {
                const icon = this.querySelector('.file-icon');
                const originalIcon = icon.textContent;
                icon.innerHTML = '<div class="loading"></div>';
                
                // Restore icon if navigation fails
                setTimeout(() => {
                    if (icon.innerHTML.includes('loading')) {
                        icon.textContent = originalIcon;
                    }
                }, 5000);
            });
        });

        // Add context menu prevention for security
        document.addEventListener('contextmenu', function(e) {
            if (e.target.closest('.download-btn') || e.target.closest('.view-btn')) {
                e.preventDefault();
            }
        });

        // Add file type filtering (future enhancement)
        function filterFiles(type) {
            const items = document.querySelectorAll('.file-item');
            items.forEach(item => {
                const isDirectory = item.classList.contains('directory');
                const shouldShow = type === 'all' || 
                                 (type === 'directories' && isDirectory) || 
                                 (type === 'files' && !isDirectory);
                
                item.style.display = shouldShow ? 'block' : 'none';
            });
        }

        // Add search functionality (future enhancement)
        function searchFiles(query) {
            const items = document.querySelectorAll('.file-item');
            const searchTerm = query.toLowerCase();
            
            items.forEach(item => {
                const fileName = item.querySelector('.file-name').textContent.toLowerCase();
                const shouldShow = fileName.includes(searchTerm);
                item.style.display = shouldShow ? 'block' : 'none';
            });
        }

        // File operations functionality
        function toggleFileOperations() {
            const dropdown = document.getElementById('operationsDropdown');
            dropdown.classList.toggle('show');
        }

        function showUploadDialog() {
            document.getElementById('uploadModal').style.display = 'block';
            toggleFileOperations();
        }

        function showCreateFolderDialog() {
            document.getElementById('createFolderModal').style.display = 'block';
            toggleFileOperations();
        }

        // Track if any files were restored during this trash session
        let filesRestored = false;

        function showTrashDialog() {
            filesRestored = false; // Reset the flag when opening trash
            loadTrashContents();
            document.getElementById('trashModal').style.display = 'block';
            toggleFileOperations();
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
            
            // If closing trash modal and files were restored, reload the page
            if (modalId === 'trashModal' && filesRestored) {
                refreshPage();
            }
        }

        function handleFileUpload() {
            const form = document.getElementById('uploadForm');
            const formData = new FormData(form);
            
            // Show upload progress
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Uploading...';
            submitBtn.disabled = true;
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                // Reload page to show results
                window.location.reload();
            })
            .catch(error => {
                console.error('Upload error:', error);
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
                alert('Upload failed. Please try again.');
            });
        }

        function handleCreateFolder() {
            const form = document.getElementById('createFolderForm');
            const formData = new FormData(form);
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                window.location.reload();
            })
            .catch(error => {
                console.error('Create folder error:', error);
                alert('Failed to create folder. Please try again.');
            });
        }

        function deleteFile(filePath) {
            if (!confirm('Move this file to trash?')) return;
            
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('file_path', filePath);
            formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                window.location.reload();
            })
            .catch(error => {
                console.error('Delete error:', error);
                alert('Failed to delete file. Please try again.');
            });
        }

        function renameFile(oldPath) {
            const newName = prompt('Enter new name:');
            if (!newName) return;
            
            const formData = new FormData();
            formData.append('action', 'rename');
            formData.append('old_path', oldPath);
            formData.append('new_name', newName);
            formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                window.location.reload();
            })
            .catch(error => {
                console.error('Rename error:', error);
                alert('Failed to rename file. Please try again.');
            });
        }

        function loadTrashContents() {
            // This would be loaded via AJAX in a real implementation
            // For now, we'll reload the page with trash view
        }

        function restoreFile(trashFile) {
            const formData = new FormData();
            formData.append('action', 'restore_file');
            formData.append('trash_file', trashFile);
            formData.append('restore_dir', getCurrentDirectory());
            formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                // Check if the response contains success or error indicators
                if (data.includes('operation_success') || data.includes('restored successfully')) {
                    showNotification('File restored successfully', 'success');
                    filesRestored = true; // Mark that a file was restored
                    // Remove the item from the trash list without reloading
                    removeTrashItemFromList(trashFile);
                } else if (data.includes('operation_error') || data.includes('Failed to restore')) {
                    showNotification('Failed to restore file', 'error');
                } else {
                    showNotification('File restored successfully', 'success');
                    filesRestored = true; // Mark that a file was restored
                    // Assume success if no clear error indicators
                    removeTrashItemFromList(trashFile);
                }
            })
            .catch(error => {
                console.error('Restore error:', error);
                showNotification('Failed to restore file. Please try again.', 'error');
            });
        }

        function removeTrashItemFromList(trashFile) {
            // Find and remove the trash item from the DOM
            const trashItems = document.querySelectorAll('.trash-item');
            trashItems.forEach(item => {
                const restoreButton = item.querySelector('.btn-restore');
                if (restoreButton && restoreButton.getAttribute('onclick').includes(trashFile)) {
                    item.style.animation = 'fadeOut 0.3s ease-out';
                    setTimeout(() => {
                        item.remove();
                        // Check if trash is now empty
                        checkIfTrashEmpty();
                    }, 300);
                }
            });
        }

        function checkIfTrashEmpty() {
            const remainingItems = document.querySelectorAll('.trash-item');
            if (remainingItems.length === 0) {
                // Show empty trash message
                const trashContents = document.getElementById('trashContents');
                trashContents.innerHTML = `
                    <p style="text-align: center; color: var(--text-muted); padding: 40px;">
                        🗑️ Trash is empty
                    </p>
                `;
            }
        }

        function showNotification(message, type = 'info') {
            // Remove any existing notifications
            const existingNotification = document.querySelector('.notification');
            if (existingNotification) {
                existingNotification.remove();
            }

            // Create notification element
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <span class="notification-message">${message}</span>
                <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
            `;

            // Add to page
            document.body.appendChild(notification);

            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 5000);
        }

        function restoreAllFiles() {
            if (!confirm('Restore all files from trash?')) return;
            
            const trashItems = document.querySelectorAll('.trash-item');
            if (trashItems.length === 0) {
                showNotification('Trash is already empty', 'info');
                return;
            }
            
            let restoredCount = 0;
            let totalCount = trashItems.length;
            
            trashItems.forEach(item => {
                const restoreButton = item.querySelector('.btn-restore');
                if (restoreButton) {
                    const onclickAttr = restoreButton.getAttribute('onclick');
                    const trashFile = onclickAttr.match(/restoreFile\('([^']+)'\)/)[1];
                    
                    const formData = new FormData();
                    formData.append('action', 'restore_file');
                    formData.append('trash_file', trashFile);
                    formData.append('restore_dir', getCurrentDirectory());
                    formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
                    
                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.text())
                    .then(data => {
                        restoredCount++;
                        filesRestored = true; // Mark that files were restored
                        item.style.animation = 'fadeOut 0.3s ease-out';
                        setTimeout(() => {
                            item.remove();
                            if (restoredCount === totalCount) {
                                showNotification(`Successfully restored ${restoredCount} files`, 'success');
                                checkIfTrashEmpty();
                            }
                        }, 300);
                    })
                    .catch(error => {
                        console.error('Restore error:', error);
                        showNotification(`Failed to restore some files`, 'error');
                    });
                }
            });
        }

        function emptyTrash() {
            if (!confirm('Permanently delete all files in trash? This cannot be undone!')) return;
            
            const formData = new FormData();
            formData.append('action', 'empty_trash');
            formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    // Clear the trash display
                    const trashContents = document.getElementById('trashContents');
                    trashContents.innerHTML = `
                        <p style="text-align: center; color: var(--text-muted); padding: 40px;">
                            🗑️ Trash is empty
                        </p>
                    `;
                } else {
                    showNotification(data.message || 'Failed to empty trash', 'error');
                }
            })
            .catch(error => {
                console.error('Empty trash error:', error);
                showNotification('Failed to empty trash. Please try again.', 'error');
            });
        }

        function refreshPage() {
            // Use GET request to avoid form resubmission
            const currentUrl = new URL(window.location);
            // Remove any POST data by navigating to the same URL with GET
            window.location.href = currentUrl.href;
        }

        function getCurrentDirectory() {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('dir') || '';
        }

        // Drag and drop file upload
        function setupDragAndDrop() {
            const uploadArea = document.getElementById('fileUploadArea');
            if (!uploadArea) return;
            
            uploadArea.addEventListener('dragover', function(e) {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', function(e) {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', function(e) {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    document.getElementById('fileInput').files = files;
                    document.getElementById('selectedFileName').textContent = files[0].name;
                }
            });
            
            uploadArea.addEventListener('click', function() {
                document.getElementById('fileInput').click();
            });
        }

        // Close modals when clicking outside
        window.addEventListener('click', function(e) {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
            
            // Close dropdowns when clicking outside
            if (!e.target.closest('.admin-controls')) {
                document.getElementById('operationsDropdown').classList.remove('show');
            }
            if (!e.target.closest('.view-selector')) {
                document.getElementById('viewDropdown').classList.remove('show');
            }
        });

        // Admin dropdown toggle function
        function toggleAdminDropdown(button) {
            // Close all other dropdowns first
            document.querySelectorAll('.admin-dropdown.show').forEach(dropdown => {
                if (dropdown !== button.parentElement) {
                    dropdown.classList.remove('show');
                }
            });
            
            // Toggle current dropdown
            button.parentElement.classList.toggle('show');
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.admin-dropdown')) {
                document.querySelectorAll('.admin-dropdown.show').forEach(dropdown => {
                    dropdown.classList.remove('show');
                });
            }
        });

        // Admin file operations functions
        function showRenameModal(filePath, currentName) {
            const modal = document.getElementById('renameModal');
            const input = document.getElementById('renameInput');
            const form = document.getElementById('renameForm');
            
            if (!modal || !input || !form) {
                // Create rename modal if it doesn't exist
                createRenameModal();
                return showRenameModal(filePath, currentName);
            }
            
            input.value = currentName;
            form.querySelector('input[name="old_path"]').value = filePath;
            modal.style.display = 'block';
            input.focus();
            input.select();
        }

        function confirmDelete(filePath, fileName) {
            if (confirm(`Move "${fileName}" to trash?`)) {
                deleteFile(filePath);
            }
        }

        function deleteFile(filePath) {
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('file_path', filePath);
            formData.append('csrf_token', '<?php echo generateCSRFToken(); ?>');
            
            fetch(window.location.href, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                // Reload the page to show updated file list
                window.location.reload();
            })
            .catch(error => {
                console.error('Delete error:', error);
                alert('Failed to delete file. Please try again.');
            });
        }

        function createRenameModal() {
            const modalHTML = `
                <div id="renameModal" class="modal">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3>Rename File/Folder</h3>
                            <span class="close" onclick="document.getElementById('renameModal').style.display='none'">&times;</span>
                        </div>
                        <form id="renameForm" method="post" action="">
                            <input type="hidden" name="action" value="rename">
                            <input type="hidden" name="old_path" value="">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-group">
                                <label for="renameInput">New Name:</label>
                                <input type="text" id="renameInput" name="new_name" class="form-input" required>
                            </div>
                            
                            <div class="form-actions">
                                <button type="button" class="btn btn-secondary" onclick="document.getElementById('renameModal').style.display='none'">Cancel</button>
                                <button type="submit" class="btn btn-primary">Rename</button>
                            </div>
                        </form>
                    </div>
                </div>
            `;
            document.body.insertAdjacentHTML('beforeend', modalHTML);
        }

        // Initialize drag and drop when page loads
        document.addEventListener('DOMContentLoaded', function() {
            setupDragAndDrop();
        });

        console.log('** BetterIndex loaded successfully! **');
        console.log('- Press ESC to go back to parent directory');
        console.log('- Theme preference saved in localStorage');
        console.log('- View preference saved in localStorage');
        console.log('- Default theme: ' + DEFAULT_THEME);
        console.log('- Default view: ' + DEFAULT_VIEW);
        <?php if ($auth_enabled && isset($current_user) && $current_user['role'] === 'admin'): ?>
        console.log('- Admin file operations enabled');
        <?php endif; ?>
    </script>

    <!-- File Operations Modals (Admin Only) -->
    <?php if ($auth_enabled && isset($current_user) && $current_user['role'] === 'admin'): ?>
    
    <!-- Upload Modal -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">
                    <span>📤</span>
                    Upload File
                </div>
                <button class="close-btn" onclick="closeModal('uploadModal')">&times;</button>
            </div>
            
            <form id="uploadForm" onsubmit="event.preventDefault(); handleFileUpload();">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="target_dir" value="<?php echo sanitizeOutput($current_dir); ?>">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                
                <div class="form-group">
                    <div id="fileUploadArea" class="file-upload-area">
                        <div class="upload-icon">📁</div>
                        <div class="upload-text">Click to select file or drag and drop</div>
                        <div class="upload-subtext">Maximum size: <?php echo formatFileSize($max_upload_size); ?></div>
                        <div id="selectedFileName" class="selected-filename"></div>
                    </div>
                    <input type="file" id="fileInput" name="file" style="display: none;" onchange="document.getElementById('selectedFileName').textContent = this.files[0]?.name || '';" required>
                </div>
                
                <div class="modal-actions">
                    <button type="button" class="btn-secondary" onclick="closeModal('uploadModal')">Cancel</button>
                    <button type="submit" class="btn-primary">Upload File</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Create Folder Modal -->
    <div id="createFolderModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">
                    <span>📁</span>
                    Create Folder
                </div>
                <button class="close-btn" onclick="closeModal('createFolderModal')">&times;</button>
            </div>
            
            <form id="createFolderForm" onsubmit="event.preventDefault(); handleCreateFolder();">
                <input type="hidden" name="action" value="create_folder">
                <input type="hidden" name="parent_dir" value="<?php echo sanitizeOutput($current_dir); ?>">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                
                <div class="form-group">
                    <label class="form-label">Folder Name</label>
                    <input type="text" name="folder_name" class="form-input" placeholder="Enter folder name" required>
                </div>
                
                <div class="modal-actions">
                    <button type="button" class="btn-secondary" onclick="closeModal('createFolderModal')">Cancel</button>
                    <button type="submit" class="btn-primary">Create Folder</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Trash Modal -->
    <div id="trashModal" class="modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <div class="modal-title">
                    <span>🗑️</span>
                    Trash
                </div>
                <button class="close-btn" onclick="closeModal('trashModal')">&times;</button>
            </div>
            
            <div id="trashContents">
                <?php
                $trash_items = getTrashContents($trash_folder);
                if (empty($trash_items)): ?>
                    <p style="text-align: center; color: var(--text-muted); padding: 40px;">
                        🗑️ Trash is empty
                    </p>
                <?php else: ?>
                    <div class="trash-header">
                        <button class="btn-secondary" onclick="restoreAllFiles()" style="margin-right: 12px;">↩️ Restore All</button>
                        <button class="btn-danger" onclick="emptyTrash()">🗑️ Empty Trash</button>
                    </div>
                    <div class="trash-items-list">
                    <?php foreach ($trash_items as $item): ?>
                        <div class="trash-item">
                            <div class="trash-item-info">
                                <div class="trash-item-name">
                                    <?php echo ($item['type'] === 'folder') ? '📁 ' : '📄 '; ?>
                                    <?php echo sanitizeOutput($item['original_name']); ?>
                                </div>
                                <div class="trash-item-meta">
                                    Deleted: <?php echo sanitizeOutput($item['deleted_date']); ?> • 
                                    Size: <?php echo formatFileSize($item['size']); ?> •
                                    Type: <?php echo ucfirst($item['type']); ?>
                                </div>
                            </div>
                            <div class="trash-actions">
                                <button class="btn-small btn-restore" onclick="restoreFile('<?php echo sanitizeOutput($item['trash_name']); ?>')">
                                    ↩️ Restore
                                </button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <?php endif; ?>

</body>
</html>
