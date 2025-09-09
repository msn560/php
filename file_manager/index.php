<?php
/**
 * Advanced Cloud File Management System
 * Features:
 * - Profile-based multi-user support
 * - JSON-based settings management
 * - Enhanced file type support
 * - Configurable upload limits
 * - Cloud-ready architecture
 * - Dark theme optimized
 * - Settings management interface
 * - Fixed file selection and upload issues
 */

session_start();

// Error handling for production
ini_set('display_errors', 0);
error_reporting(0);

// Default configuration
$defaultSettings = [
    'admin_password' => 'admin123',
    'max_upload_bytes' => 500 * 1024 * 1024, // 500MB (increased)
    'allowed_profiles' => ['admin', 'user', 'guest'],
    'theme' => 'dark',
    'auto_refresh' => false,
    'show_hidden_files' => false,
    'default_view' => 'grid',
    'items_per_page' => 50,
    'enable_thumbnails' => true,
    'allowed_mime_types' => [
        // Images
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/svg+xml',
        'image/tiff', 'image/x-icon', 'image/avif', 'image/heic', 'image/heif',
        // Videos
        'video/mp4', 'video/webm', 'video/ogg', 'video/avi', 'video/mov', 'video/wmv', 'video/mkv',
        'video/flv', 'video/3gp', 'video/m4v', 'video/quicktime',
        // Audio
        'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/mpeg', 'audio/aac', 'audio/flac', 'audio/m4a',
        'audio/wma', 'audio/aiff', 'audio/opus',
        // Documents
        'application/pdf', 'text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/rtf', 'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet',
        // Archives
        'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/x-tar',
        'application/gzip', 'application/x-bzip2', 'application/x-xz',
        // Code files
        'application/json', 'application/xml', 'text/xml', 'application/javascript',
        'text/x-php', 'text/x-python', 'text/x-java-source', 'text/x-c', 'text/x-c++',
        'text/x-csharp', 'text/x-ruby', 'text/x-go', 'text/x-rust', 'text/x-swift',
        // 3D and CAD
        'model/obj', 'model/gltf+json', 'model/gltf-binary', 'application/x-blender',
        // Fonts
        'font/ttf', 'font/otf', 'font/woff', 'font/woff2', 'application/font-sfnt',
        // Others
        'application/octet-stream', 'application/x-executable', 'application/x-deb',
        'application/x-rpm', 'application/x-msi', 'application/x-dmg'
    ]
];

// Settings file path
define('SETTINGS_FILE', __DIR__ . '/settings.json');
define('PROFILES_FILE', __DIR__ . '/profiles.json');
define('BASE_UPLOAD_DIR', __DIR__ . DIRECTORY_SEPARATOR . 'uploads');

// Load settings
function loadSettings() {
    global $defaultSettings;
    
    if (file_exists(SETTINGS_FILE)) {
        $settings = json_decode(file_get_contents(SETTINGS_FILE), true);
        if ($settings && is_array($settings)) {
            return array_merge($defaultSettings, $settings);
        }
    }
    
    // Create default settings file
    saveSettings($defaultSettings);
    return $defaultSettings;
}

// Save settings
function saveSettings($settings) {
    $json = json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    return file_put_contents(SETTINGS_FILE, $json) !== false;
}

// Load profiles
function loadProfiles() {
    if (file_exists(PROFILES_FILE)) {
        $profiles = json_decode(file_get_contents(PROFILES_FILE), true);
        if ($profiles && is_array($profiles)) {
            return $profiles;
        }
    }
    
    $defaultProfiles = [
        'admin' => [
            'name' => 'Administrator',
            'permissions' => ['read', 'write', 'delete', 'settings'],
            'upload_limit' => 0, // unlimited
            'allowed_extensions' => '*'
        ],
        'user' => [
            'name' => 'Standard User',
            'permissions' => ['read', 'write'],
            'upload_limit' => 100 * 1024 * 1024, // 100MB
            'allowed_extensions' => 'jpg,jpeg,png,gif,pdf,doc,docx,txt'
        ],
        'guest' => [
            'name' => 'Guest User',
            'permissions' => ['read'],
            'upload_limit' => 0,
            'allowed_extensions' => ''
        ]
    ];
    
    file_put_contents(PROFILES_FILE, json_encode($defaultProfiles, JSON_PRETTY_PRINT));
    return $defaultProfiles;
}

// Get current settings
$settings = loadSettings();
$profiles = loadProfiles();

// Define constants from settings
define('ADMIN_PASSWORD', $settings['admin_password']);
define('MAX_UPLOAD_BYTES', $settings['max_upload_bytes']);
$ALLOWED_MIME_TYPES = $settings['allowed_mime_types'];

// Security functions
function is_subpath(string $base, string $path): bool {
    $base = rtrim(realpath($base) ?: '', DIRECTORY_SEPARATOR);
    $path = rtrim(realpath($path) ?: '', DIRECTORY_SEPARATOR);
    return $base !== '' && $path !== '' && strpos($path, $base) === 0;
}

function sanitize_name(string $name): string {
    $name = trim($name);
    $name = preg_replace('/[^\p{L}\p{N}\-_\.\s]/u', '', $name);
    $name = preg_replace('/\s+/', '_', $name);
    return substr($name, 0, 200);
}

function get_file_icon(string $mime): array {
    $icons = [
        'image/' => ['fas fa-image', 'success'],
        'video/' => ['fas fa-video', 'primary'],
        'audio/' => ['fas fa-music', 'info'],
        'application/pdf' => ['fas fa-file-pdf', 'danger'],
        'text/' => ['fas fa-file-alt', 'info'],
        'application/zip' => ['fas fa-file-archive', 'warning'],
        'application/x-rar' => ['fas fa-file-archive', 'warning'],
        'application/x-7z' => ['fas fa-file-archive', 'warning'],
        'application/msword' => ['fas fa-file-word', 'primary'],
        'application/vnd.openxml' => ['fas fa-file-word', 'primary'],
        'application/vnd.ms-excel' => ['fas fa-file-excel', 'success'],
        'application/json' => ['fas fa-code', 'secondary'],
        'application/xml' => ['fas fa-code', 'secondary'],
        'text/javascript' => ['fab fa-js-square', 'warning'],
        'text/css' => ['fab fa-css3-alt', 'info'],
        'text/html' => ['fab fa-html5', 'danger'],
        'font/' => ['fas fa-font', 'info'],
        'model/' => ['fas fa-cube', 'warning'],
        'text/x-php' => ['fab fa-php', 'primary'],
        'text/x-python' => ['fab fa-python', 'success'],
        'text/x-java' => ['fab fa-java', 'danger'],
    ];
    
    foreach ($icons as $type => $icon) {
        if (strpos($mime, $type) === 0) {
            return $icon;
        }
    }
    return ['fas fa-file', 'muted'];
}

function format_file_size(int $size): string {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $unit = 0;
    while ($size >= 1024 && $unit < 4) {
        $size /= 1024;
        $unit++;
    }
    return round($size, 2) . ' ' . $units[$unit];
}

function serve_file(string $filepath, bool $download = false) {
    if (!file_exists($filepath) || !is_file($filepath)) {
        http_response_code(404);
        echo json_encode(['error' => 'File not found']);
        exit();
    }
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filepath) ?: 'application/octet-stream';
    finfo_close($finfo);

    header('Content-Type: ' . ($download ? 'application/octet-stream' : $mime));
    if ($download) {
        header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
    }
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: private, must-revalidate');

    while (ob_get_level()) ob_end_clean();
    readfile($filepath);
    exit();
}

function delete_file_or_folder(string $path): bool {
    if (is_file($path)) {
        return unlink($path);
    } elseif (is_dir($path)) {
        return rmdir_recursive($path);
    }
    return false;
}

function rmdir_recursive(string $dir): bool {
    if (!is_dir($dir)) return false;
    
    $files = scandir($dir);
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        if (is_dir($path)) {
            rmdir_recursive($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}

// Initialize upload directory
if (!is_dir(BASE_UPLOAD_DIR)) {
    mkdir(BASE_UPLOAD_DIR, 0755, true);
}

// Create .htaccess for security
$htaccessPath = BASE_UPLOAD_DIR . DIRECTORY_SEPARATOR . '.htaccess';
if (!file_exists($htaccessPath)) {
    @file_put_contents($htaccessPath,
        "Options -Indexes\n" .
        "php_flag engine off\n" .
        "<IfModule mod_headers.c>\n" .
        "Header set X-Content-Type-Options nosniff\n" .
        "Header set X-Frame-Options DENY\n" .
        "</IfModule>\n"
    );
}

// Settings API
if (isset($_GET['api']) && $_GET['api'] === 'settings') {
    header('Content-Type: application/json');
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        echo json_encode(['settings' => $settings, 'profiles' => $profiles]);
        exit();
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Check if user has settings permission
        if (!isset($_SESSION['profile']) || !in_array('settings', $profiles[$_SESSION['profile']]['permissions'] ?? [])) {
            echo json_encode(['error' => 'Permission denied']);
            exit();
        }
        
        $data = json_decode(file_get_contents('php://input'), true);
        if (isset($data['settings'])) {
            if (saveSettings($data['settings'])) {
                echo json_encode(['success' => true, 'message' => 'Settings saved successfully']);
            } else {
                echo json_encode(['error' => 'Failed to save settings']);
            }
        } elseif (isset($data['profiles'])) {
            if (file_put_contents(PROFILES_FILE, json_encode($data['profiles'], JSON_PRETTY_PRINT))) {
                echo json_encode(['success' => true, 'message' => 'Profiles saved successfully']);
            } else {
                echo json_encode(['error' => 'Failed to save profiles']);
            }
        }
        exit();
    }
}

// Logout handler
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    setcookie('file_upload_auth', '', time() - 3600, "/");
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit();
}

// Login check
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    $loginError = null;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'], $_POST['profile'])) {
        if (hash_equals((string)ADMIN_PASSWORD, (string)$_POST['password'])) {
            $selectedProfile = $_POST['profile'];
            if (array_key_exists($selectedProfile, $profiles)) {
                session_regenerate_id(true);
                $_SESSION['loggedin'] = true;
                $_SESSION['profile'] = $selectedProfile;
                $_SESSION['login_time'] = time();
                setcookie('file_upload_auth', '1', time() + (86400 * 30), "/", "", 
                    isset($_SERVER['HTTPS']), true);
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit();
            } else {
                $loginError = "Invalid profile selected!";
            }
        } else {
            $loginError = "Invalid password! Please try again.";
        }
    }

    // Login form
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cloud File Manager - Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #6366f1;
                --secondary: #8b5cf6;
                --dark: #0f172a;
                --darker: #020617;
                --text-light: #f1f5f9;
            }
            
            body {
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                min-height: 100vh;
                display: flex;
                align-items: center;
                font-family: 'Inter', system-ui, sans-serif;
                overflow: hidden;
                color: var(--text-light);
            }
            
            .login-container {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 24px;
                padding: 3rem 2rem;
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
                color: white;
                max-width: 420px;
                width: 100%;
            }
            
            .login-icon {
                font-size: 4rem;
                margin-bottom: 1rem;
                background: linear-gradient(135deg, #fbbf24, #f59e0b);
                -webkit-background-clip: text;
                background-clip: text;
                -webkit-text-fill-color: transparent;
                animation: pulse 2s ease-in-out infinite;
            }
            
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }
            
            .form-control, .form-select {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 12px;
                color: white;
                padding: 1rem;
                transition: all 0.3s ease;
            }
            
            .form-control:focus, .form-select:focus {
                background: rgba(255, 255, 255, 0.15);
                border-color: rgba(255, 255, 255, 0.5);
                box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.25);
                color: white;
            }
            
            .form-control::placeholder {
                color: rgba(255, 255, 255, 0.7);
            }
            
            .form-select option {
                background: var(--dark);
                color: var(--text-light);
            }
            
            .btn-login {
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.1));
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 12px;
                padding: 1rem;
                font-weight: 600;
                transition: all 0.3s ease;
                color: white;
            }
            
            .btn-login:hover {
                background: rgba(255, 255, 255, 0.2);
                transform: translateY(-3px);
                color: white;
            }
            
            .alert {
                background: rgba(239, 68, 68, 0.2);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #fff;
                border-radius: 12px;
            }
            
            .input-group-text {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.3);
                color: rgba(255, 255, 255, 0.7);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 col-lg-5">
                    <div class="login-container text-center">
                        <i class="fas fa-cloud login-icon"></i>
                        <h2 class="mb-2">Cloud File Manager</h2>
                        <p class="mb-4 opacity-75">Secure access required</p>
                        
                        <?php if ($loginError): ?>
                        <div class="alert alert-danger" role="alert">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <?php echo htmlspecialchars($loginError); ?>
                        </div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="mb-3">
                                <select name="profile" class="form-select" required>
                                    <option value="">Select Profile</option>
                                    <?php foreach ($profiles as $key => $profile): ?>
                                    <option value="<?php echo $key; ?>"><?php echo htmlspecialchars($profile['name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="mb-4">
                                <div class="input-group">
                                    <span class="input-group-text">
                                        <i class="fas fa-lock"></i>
                                    </span>
                                    <input type="password" class="form-control border-start-0" 
                                           name="password" placeholder="Enter your password" required>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-login w-100">
                                <i class="fas fa-sign-in-alt me-2"></i> Access System
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// Get current profile
$currentProfile = $_SESSION['profile'] ?? 'guest';
$userPermissions = $profiles[$currentProfile]['permissions'] ?? ['read'];

// API endpoints
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['api']) {
        case 'download':
            if (!isset($_GET['path'])) {
                echo json_encode(['error' => 'Path required']);
                exit();
            }
            
            $relPath = base64_decode($_GET['path'], true);
            if ($relPath === false) {
                echo json_encode(['error' => 'Invalid path']);
                exit();
            }
            
            $fullPath = BASE_UPLOAD_DIR . DIRECTORY_SEPARATOR . $relPath;
            if (!is_subpath(BASE_UPLOAD_DIR, $fullPath)) {
                echo json_encode(['error' => 'Access denied']);
                exit();
            }
            
            serve_file($fullPath, true);
            break;
            
        case 'preview':
            if (!isset($_GET['path'])) {
                echo json_encode(['error' => 'Path required']);
                exit();
            }
            
            $relPath = base64_decode($_GET['path'], true);
            if ($relPath === false) {
                echo json_encode(['error' => 'Invalid path']);
                exit();
            }
            
            $fullPath = BASE_UPLOAD_DIR . DIRECTORY_SEPARATOR . $relPath;
            if (!is_subpath(BASE_UPLOAD_DIR, $fullPath)) {
                echo json_encode(['error' => 'Access denied']);
                exit();
            }
            
            serve_file($fullPath, false);
            break;
            
        case 'delete':
            if (!in_array('delete', $userPermissions)) {
                echo json_encode(['error' => 'Permission denied']);
                exit();
            }
            
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo json_encode(['error' => 'POST required']);
                exit();
            }
            
            $data = json_decode(file_get_contents('php://input'), true);
            if (!isset($data['path'])) {
                echo json_encode(['error' => 'Path required']);
                exit();
            }
            
            $relPath = base64_decode($data['path'], true);
            if ($relPath === false) {
                echo json_encode(['error' => 'Invalid path']);
                exit();
            }
            
            $fullPath = BASE_UPLOAD_DIR . DIRECTORY_SEPARATOR . $relPath;
            if (!is_subpath(BASE_UPLOAD_DIR, $fullPath)) {
                echo json_encode(['error' => 'Access denied']);
                exit();
            }
            
            if (delete_file_or_folder($fullPath)) {
                echo json_encode(['success' => true, 'message' => 'Deleted successfully']);
            } else {
                echo json_encode(['error' => 'Delete failed']);
            }
            exit();
            
        case 'rename':
            if (!in_array('write', $userPermissions)) {
                echo json_encode(['error' => 'Permission denied']);
                exit();
            }
            
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo json_encode(['error' => 'POST required']);
                exit();
            }
            
            $data = json_decode(file_get_contents('php://input'), true);
            if (!isset($data['oldPath'], $data['newName'])) {
                echo json_encode(['error' => 'Old path and new name required']);
                exit();
            }
            
            $relPath = base64_decode($data['oldPath'], true);
            if ($relPath === false) {
                echo json_encode(['error' => 'Invalid path']);
                exit();
            }
            
            $oldPath = BASE_UPLOAD_DIR . DIRECTORY_SEPARATOR . $relPath;
            $newName = sanitize_name($data['newName']);
            $newPath = dirname($oldPath) . DIRECTORY_SEPARATOR . $newName;
            
            if (!is_subpath(BASE_UPLOAD_DIR, $oldPath) || !is_subpath(BASE_UPLOAD_DIR, $newPath)) {
                echo json_encode(['error' => 'Access denied']);
                exit();
            }
            
            if (rename($oldPath, $newPath)) {
                echo json_encode(['success' => true, 'message' => 'Renamed successfully']);
            } else {
                echo json_encode(['error' => 'Rename failed']);
            }
            exit();
            
        default:
            echo json_encode(['error' => 'Unknown API endpoint']);
            exit();
    }
}

// Current directory logic
$baseReal = realpath(BASE_UPLOAD_DIR);
$currentDir = $baseReal;
$relativeDir = '';

if (isset($_GET['dir'])) {
    $requestedDir = base64_decode($_GET['dir'], true);
    if ($requestedDir !== false) {
        $requestedDir = str_replace(['..', "\0"], '', $requestedDir);
        $candidate = realpath($baseReal . DIRECTORY_SEPARATOR . $requestedDir);
        if ($candidate && is_subpath($baseReal, $candidate)) {
            $currentDir = $candidate;
            $relativeDir = $requestedDir;
        }
    }
}

// Handle POST requests
$response = ['success' => false, 'message' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create new folder
    if (isset($_POST['action']) && $_POST['action'] === 'create_folder') {
        if (!in_array('write', $userPermissions)) {
            $response['error'] = 'Permission denied';
        } else {
            $folderName = sanitize_name($_POST['folder_name'] ?? '');
            if (empty($folderName)) {
                $response['error'] = 'Invalid folder name';
            } else {
                $folderPath = $currentDir . DIRECTORY_SEPARATOR . $folderName;
                if (!is_dir($folderPath)) {
                    if (mkdir($folderPath, 0755)) {
                        $response['success'] = true;
                        $response['message'] = 'Folder created successfully';
                        @file_put_contents($folderPath . DIRECTORY_SEPARATOR . '.htaccess', 
                            "Options -Indexes\nphp_flag engine off\n");
                    } else {
                        $response['error'] = 'Failed to create folder';
                    }
                } else {
                    $response['error'] = 'Folder already exists';
                }
            }
        }
        
        if (isset($_POST['ajax'])) {
            header('Content-Type: application/json');
            echo json_encode($response);
            exit();
        }
    }
    
    // File upload
    if (isset($_FILES['files'])) {
        if (!in_array('write', $userPermissions)) {
            $response['error'] = 'Permission denied';
            if (isset($_POST['ajax'])) {
                header('Content-Type: application/json');
                echo json_encode($response);
                exit();
            }
        } else {
            $uploadResults = [];
            $files = $_FILES['files'];
            
            // Handle multiple files
            if (!is_array($files['name'])) {
                $files = [
                    'name' => [$files['name']],
                    'type' => [$files['type']],
                    'tmp_name' => [$files['tmp_name']],
                    'error' => [$files['error']],
                    'size' => [$files['size']]
                ];
            }
            
            $userUploadLimit = $profiles[$currentProfile]['upload_limit'] ?? MAX_UPLOAD_BYTES;
            
            for ($i = 0; $i < count($files['name']); $i++) {
                if ($files['error'][$i] !== UPLOAD_ERR_OK) continue;
                
                // Check user upload limit
                if ($userUploadLimit > 0 && $files['size'][$i] > $userUploadLimit) {
                    $uploadResults[] = [
                        'success' => false,
                        'filename' => $files['name'][$i],
                        'error' => 'File size exceeds your limit: ' . format_file_size($userUploadLimit)
                    ];
                    continue;
                }
                
                // Verify MIME type
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = finfo_file($finfo, $files['tmp_name'][$i]);
                finfo_close($finfo);
                
                if (!in_array($mime, $ALLOWED_MIME_TYPES, true)) {
                    $uploadResults[] = [
                        'success' => false,
                        'filename' => $files['name'][$i],
                        'error' => 'Unsupported file type: ' . $mime
                    ];
                    continue;
                }
                
                if ($files['size'][$i] > MAX_UPLOAD_BYTES) {
                    $uploadResults[] = [
                        'success' => false,
                        'filename' => $files['name'][$i],
                        'error' => 'File size exceeds system limit: ' . format_file_size(MAX_UPLOAD_BYTES)
                    ];
                    continue;
                }
                
                $safeName = sanitize_name(basename($files['name'][$i]));
                if (empty($safeName)) $safeName = 'file_' . time() . '_' . $i;
                
                $targetPath = $currentDir . DIRECTORY_SEPARATOR . $safeName;
                
                // Handle duplicate names
                $counter = 1;
                $nameOnly = pathinfo($safeName, PATHINFO_FILENAME);
                $ext = pathinfo($safeName, PATHINFO_EXTENSION);
                
                while (file_exists($targetPath)) {
                    $safeName = $nameOnly . '_' . $counter . ($ext ? '.' . $ext : '');
                    $targetPath = $currentDir . DIRECTORY_SEPARATOR . $safeName;
                    $counter++;
                }
                
                if (move_uploaded_file($files['tmp_name'][$i], $targetPath)) {
                    @chmod($targetPath, 0644);
                    $uploadResults[] = [
                        'success' => true,
                        'filename' => $safeName,
                        'message' => 'Uploaded successfully'
                    ];
                } else {
                    $uploadResults[] = [
                        'success' => false,
                        'filename' => $files['name'][$i],
                        'error' => 'Upload failed'
                    ];
                }
            }
            
            if (isset($_POST['ajax'])) {
                header('Content-Type: application/json');
                echo json_encode(['results' => $uploadResults]);
                exit();
            }
        }
    }
}

// Get directory contents
$folders = [];
$files = [];

if ($dh = opendir($currentDir)) {
    while (($entry = readdir($dh)) !== false) {
        if ($entry === "." || $entry === ".." || ($entry[0] === '.' && !$settings['show_hidden_files'])) continue;
        
        $fullPath = $currentDir . DIRECTORY_SEPARATOR . $entry;
        
        if (is_dir($fullPath)) {
            $folders[] = [
                'name' => $entry,
                'path' => ($relativeDir ? $relativeDir . DIRECTORY_SEPARATOR : '') . $entry,
                'modified' => filemtime($fullPath)
            ];
        } else {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $fullPath) ?: 'application/octet-stream';
            finfo_close($finfo);
            
            $iconData = get_file_icon($mime);
            
            $files[] = [
                'name' => $entry,
                'path' => ($relativeDir ? $relativeDir . DIRECTORY_SEPARATOR : '') . $entry,
                'size' => filesize($fullPath),
                'modified' => filemtime($fullPath),
                'mime' => $mime,
                'icon' => $iconData[0],
                'color' => $iconData[1]
            ];
        }
    }
    closedir($dh);
}

// Sort arrays
usort($folders, fn($a, $b) => strcasecmp($a['name'], $b['name']));
usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));

// Create breadcrumbs
$breadcrumbs = [];
if ($relativeDir) {
    $parts = explode(DIRECTORY_SEPARATOR, $relativeDir);
    $accumulated = '';
    foreach ($parts as $part) {
        if (empty($part)) continue;
        $accumulated .= ($accumulated ? DIRECTORY_SEPARATOR : '') . $part;
        $breadcrumbs[] = [
            'name' => $part,
            'path' => base64_encode($accumulated)
        ];
    }
}

// Helper functions
function folderUrl($path = '') {
    return '?dir=' . urlencode(base64_encode($path));
}

function apiUrl($action, $path) {
    return '?api=' . $action . '&path=' . urlencode(base64_encode($path));
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud File Manager Pro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-primary: #6366f1;
            --accent-secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
            --border: rgba(255, 255, 255, 0.1);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, #0a0f1c 100%);
            color: var(--text-primary);
            min-height: 100vh;
            margin: 0;
            overflow-x: hidden;
        }

        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 320px;
            height: 100vh;
            background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            backdrop-filter: blur(20px);
            border-right: 1px solid var(--border);
            z-index: 1000;
            transition: transform 0.3s ease;
            overflow-y: auto;
        }

        .sidebar::-webkit-scrollbar {
            width: 6px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: transparent;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: var(--accent-primary);
            border-radius: 3px;
        }

        .main-content {
            margin-left: 320px;
            padding: 2rem;
            min-height: 100vh;
        }

        .sidebar-header {
            padding: 2rem 1.5rem 1.5rem;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            margin-bottom: 1.5rem;
        }

        .sidebar-header h4 {
            color: white;
            font-weight: 700;
            margin: 0;
            font-size: 1.25rem;
        }

        .sidebar-header small {
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.875rem;
        }

        .profile-info {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.75rem;
            margin-top: 0.75rem;
            font-size: 0.8rem;
        }

        .sidebar-nav {
            padding: 0 1rem;
        }

        .nav-section {
            margin-bottom: 2rem;
        }

        .nav-title {
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
            padding: 0 0.5rem;
        }

        .nav-item {
            margin-bottom: 0.25rem;
        }

        .nav-link {
            display: flex;
            align-items: center;
            padding: 0.75rem 1rem;
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 12px;
            transition: all 0.2s ease;
            font-size: 0.875rem;
            font-weight: 500;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
            cursor: pointer;
        }

        .nav-link:hover {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            color: white;
            transform: translateX(4px);
        }

        .nav-link.active {
            background: rgba(99, 102, 241, 0.15);
            color: var(--accent-primary);
            border: 1px solid rgba(99, 102, 241, 0.2);
        }

        .nav-link i {
            width: 20px;
            margin-right: 0.75rem;
            font-size: 0.875rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            padding: 0 1rem;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            text-align: center;
            transition: all 0.2s ease;
        }

        .stat-card:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: var(--accent-primary);
        }

        .stat-number {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent-primary);
            margin-bottom: 0.25rem;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 500;
        }

        .breadcrumb {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin-bottom: 2rem;
        }

        .breadcrumb-item a {
            color: var(--accent-primary);
            text-decoration: none;
            font-weight: 500;
        }

        .breadcrumb-item a:hover {
            color: var(--accent-secondary);
        }

        .breadcrumb-item + .breadcrumb-item::before {
            color: var(--text-muted);
        }

        .header-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            flex: 1;
            max-width: 400px;
        }

        .search-box input {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            padding: 0.75rem 1rem 0.75rem 3rem;
            width: 100%;
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }

        .search-box input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            background: var(--bg-tertiary);
        }

        .search-box i {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        .upload-area {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.1));
            border: 2px dashed rgba(99, 102, 241, 0.3);
            border-radius: 16px;
            padding: 3rem 2rem;
            text-align: center;
            margin-bottom: 2rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .upload-area::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.6s ease;
        }

        .upload-area:hover::before {
            left: 100%;
        }

        .upload-area.dragover {
            border-color: var(--accent-primary);
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(139, 92, 246, 0.2));
            transform: scale(1.02);
        }

        .upload-icon {
            font-size: 3rem;
            color: var(--accent-primary);
            margin-bottom: 1rem;
            animation: float 3s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }

        .file-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1.5rem;
        }

        .file-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .file-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .file-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-lg);
            border-color: rgba(99, 102, 241, 0.3);
        }

        .file-card:hover::before {
            transform: scaleX(1);
        }

        .file-preview {
            width: 100%;
            height: 160px;
            background: var(--bg-primary);
            border-radius: 12px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }

        .file-preview img {
            max-width: 100%;
            max-height: 100%;
            object-fit: cover;
            border-radius: 8px;
            transition: transform 0.3s ease;
        }

        .file-preview:hover img {
            transform: scale(1.05);
        }

        .file-preview i {
            font-size: 2.5rem;
            opacity: 0.7;
        }

        .file-info {
            margin-bottom: 1rem;
        }

        .file-name {
            font-weight: 600;
            color: var(--text-primary);
            margin: 0 0 0.5rem 0;
            font-size: 0.875rem;
            line-height: 1.4;
            word-break: break-word;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .file-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .file-actions {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
        }

        .btn-action {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.5rem;
            border-radius: 8px;
            transition: all 0.2s ease;
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
            cursor: pointer;
        }

        .btn-action:hover {
            color: white;
            transform: scale(1.1);
        }

        .btn-download:hover {
            background: var(--success);
            border-color: var(--success);
        }

        .btn-preview:hover {
            background: var(--info);
            border-color: var(--info);
        }

        .btn-delete:hover {
            background: var(--danger);
            border-color: var(--danger);
        }

        .btn-rename:hover {
            background: var(--warning);
            border-color: var(--warning);
        }

        .modal-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 16px;
            box-shadow: var(--shadow-lg);
        }

        .modal-header {
            border-bottom: 1px solid var(--border);
            padding: 1.5rem;
        }

        .modal-body {
            padding: 1.5rem;
        }

        .modal-footer {
            border-top: 1px solid var(--border);
            padding: 1.5rem;
        }

        .form-control, .form-select {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            font-size: 0.875rem;
        }

        .form-control:focus, .form-select:focus {
            background: var(--bg-tertiary);
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            color: var(--text-primary);
        }

        .form-control::placeholder {
            color: var(--text-muted);
        }

        .form-select option {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }

        .btn {
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.875rem;
            padding: 0.75rem 1.5rem;
            transition: all 0.2s ease;
            border: none;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            color: white;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #5856eb, #7c3aed);
            transform: translateY(-2px);
            color: white;
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
            color: white;
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-success:hover {
            background: #059669;
            color: white;
        }

        .alert {
            border: none;
            border-radius: 12px;
            border-left: 4px solid;
            font-weight: 500;
            font-size: 0.875rem;
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
        }

        .alert-success {
            border-left-color: var(--success);
        }

        .alert-danger {
            border-left-color: var(--danger);
        }

        .alert-warning {
            border-left-color: var(--warning);
        }

        .progress {
            height: 8px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-bar {
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .context-menu {
            position: fixed;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.5rem 0;
            box-shadow: var(--shadow-lg);
            z-index: 10000;
            min-width: 180px;
            backdrop-filter: blur(20px);
        }

        .context-item {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: background 0.2s ease;
            color: var(--text-primary);
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .context-item:hover {
            background: var(--accent-primary);
            color: white;
        }

        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-muted);
        }

        .empty-state i {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        }

        .toast {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            box-shadow: var(--shadow-lg);
            backdrop-filter: blur(20px);
        }

        .mobile-toggle {
            display: none;
            position: fixed;
            top: 1rem;
            left: 1rem;
            z-index: 1100;
            background: var(--accent-primary);
            color: white;
            border: none;
            border-radius: 12px;
            width: 48px;
            height: 48px;
            box-shadow: var(--shadow);
        }

        /* Settings Panel */
        .settings-panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .settings-panel h5 {
            color: var(--text-primary);
            margin-bottom: 1rem;
        }

        .setting-item {
            margin-bottom: 1.5rem;
        }

        .setting-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            display: block;
        }

        /* Mobile Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
                width: 300px;
            }
            
            .sidebar.show {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
                padding: 1rem;
            }
            
            .mobile-toggle {
                display: flex !important;
                align-items: center;
                justify-content: center;
            }
            
            .file-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .upload-area {
                padding: 2rem 1rem;
            }
            
            .header-actions {
                flex-direction: column;
                align-items: stretch;
                gap: 1rem;
            }
            
            .search-box {
                max-width: none;
            }
        }

        /* Selection */
        .file-card.selected {
            background: rgba(99, 102, 241, 0.2);
            border-color: var(--accent-primary);
        }

        .bulk-actions {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            box-shadow: var(--shadow-lg);
            transform: translateY(100px);
            transition: transform 0.3s ease;
            backdrop-filter: blur(20px);
        }

        .bulk-actions.show {
            transform: translateY(0);
        }

        .selection-info {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }

        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-primary);
        }

        /* Animations */
        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .file-card {
            animation: slideInUp 0.3s ease forwards;
        }

        .file-card:nth-child(odd) {
            animation-delay: 0.1s;
        }

        .btn-close {
            filter: invert(1);
        }
    </style>
</head>
<body>
    <!-- Mobile Toggle -->
    <button class="mobile-toggle" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </button>

    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h4>
                <i class="fas fa-cloud me-2"></i>
                Cloud Manager
            </h4>
            <small>
                <i class="fas fa-user me-1"></i>
                <?php echo htmlspecialchars($profiles[$currentProfile]['name']); ?> | <?php echo date('M d, Y H:i'); ?>
            </small>
            <div class="profile-info">
                <div><strong>Profile:</strong> <?php echo htmlspecialchars($currentProfile); ?></div>
                <div><strong>Upload Limit:</strong> 
                    <?php 
                    $limit = $profiles[$currentProfile]['upload_limit'] ?? 0;
                    echo $limit > 0 ? format_file_size($limit) : 'Unlimited';
                    ?>
                </div>
            </div>
        </div>

        <div class="sidebar-nav">
            <!-- Statistics -->
            <div class="nav-section">
                <div class="nav-title">Statistics</div>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number"><?php echo count($folders); ?></div>
                        <div class="stat-label">Folders</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number"><?php echo count($files); ?></div>
                        <div class="stat-label">Files</div>
                    </div>
                </div>
            </div>

            <!-- Actions -->
            <div class="nav-section">
                <div class="nav-title">Actions</div>
                <div class="nav-item">
                    <button class="nav-link" onclick="document.getElementById('uploadInput').click()">
                        <i class="fas fa-upload"></i>
                        Upload Files
                    </button>
                </div>
                <?php if (in_array('write', $userPermissions)): ?>
                <div class="nav-item">
                    <button class="nav-link" data-bs-toggle="modal" data-bs-target="#folderModal">
                        <i class="fas fa-folder-plus"></i>
                        New Folder
                    </button>
                </div>
                <?php endif; ?>
                <div class="nav-item">
                    <button class="nav-link" onclick="selectAll()">
                        <i class="fas fa-check-square"></i>
                        Select All
                    </button>
                </div>
                <?php if (in_array('settings', $userPermissions)): ?>
                <div class="nav-item">
                    <button class="nav-link" data-bs-toggle="modal" data-bs-target="#settingsModal">
                        <i class="fas fa-cog"></i>
                        Settings
                    </button>
                </div>
                <?php endif; ?>
                <div class="nav-item">
                    <button class="nav-link" onclick="location.reload()">
                        <i class="fas fa-sync-alt"></i>
                        Refresh
                    </button>
                </div>
            </div>

            <!-- Navigation -->
            <div class="nav-section">
                <div class="nav-title">Navigation</div>
                <div class="nav-item">
                    <a href="<?php echo folderUrl(''); ?>" class="nav-link <?php echo $relativeDir === '' ? 'active' : ''; ?>">
                        <i class="fas fa-home"></i>
                        Home
                    </a>
                </div>
                
                <?php foreach ($folders as $folder): ?>
                <div class="nav-item">
                    <a href="<?php echo folderUrl($folder['path']); ?>" class="nav-link">
                        <i class="fas fa-folder"></i>
                        <?php echo htmlspecialchars($folder['name']); ?>
                    </a>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item">
                            <a href="<?php echo folderUrl(''); ?>">
                                <i class="fas fa-home me-1"></i>
                                Home
                            </a>
                        </li>
                        <?php foreach ($breadcrumbs as $crumb): ?>
                        <li class="breadcrumb-item">
                            <a href="?dir=<?php echo urlencode($crumb['path']); ?>">
                                <?php echo htmlspecialchars($crumb['name']); ?>
                            </a>
                        </li>
                        <?php endforeach; ?>
                    </ol>
                </nav>
                <h2 class="mb-0">
                    <i class="fas fa-folder-open me-2 text-primary"></i>
                    <?php echo $relativeDir === '' ? 'Home Directory' : htmlspecialchars(basename($currentDir)); ?>
                </h2>
            </div>
            <a href="?logout" class="btn btn-danger">
                <i class="fas fa-sign-out-alt me-2"></i>
                Logout
            </a>
        </div>

        <!-- Actions & Search -->
        <div class="header-actions">
            <div class="search-box">
                <i class="fas fa-search"></i>
                <input type="text" id="searchInput" placeholder="Search files and folders..." onkeyup="searchFiles()">
            </div>
            <?php if (in_array('write', $userPermissions)): ?>
            <button class="btn btn-primary" onclick="document.getElementById('uploadInput').click()">
                <i class="fas fa-plus me-2"></i>
                Add Files
            </button>
            <?php endif; ?>
        </div>

        <!-- Upload Area -->
        <?php if (in_array('write', $userPermissions)): ?>
        <div class="upload-area" id="dropZone" onclick="document.getElementById('uploadInput').click()">
            <i class="fas fa-cloud-upload-alt upload-icon"></i>
            <h4>Drag & drop files here or click to upload</h4>
            <p class="text-muted mb-3">
                Maximum file size: <?php echo format_file_size(MAX_UPLOAD_BYTES); ?><br>
                <small>Your limit: <?php 
                    $userLimit = $profiles[$currentProfile]['upload_limit'] ?? 0;
                    echo $userLimit > 0 ? format_file_size($userLimit) : 'Unlimited';
                ?></small>
            </p>
            
            <form id="uploadForm" method="post" enctype="multipart/form-data">
                <input type="file" name="files[]" id="uploadInput" class="d-none" multiple>
                <input type="hidden" name="ajax" value="1">
                <div class="progress d-none" id="uploadProgress">
                    <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <!-- File Grid -->
        <div class="file-grid" id="fileGrid">
            <?php foreach ($files as $file): ?>
            <div class="file-card" data-name="<?php echo htmlspecialchars(strtolower($file['name'])); ?>">
                <?php if (in_array('delete', $userPermissions)): ?>
                <input type="checkbox" class="file-select position-absolute" style="top: 1rem; left: 1rem; z-index: 10;" onchange="updateSelection()">
                <?php endif; ?>
                
                <div class="file-preview">
                    <?php if (strpos($file['mime'], 'image/') === 0): ?>
                        <img src="<?php echo apiUrl('preview', $file['path']); ?>" 
                             alt="<?php echo htmlspecialchars($file['name']); ?>"
                             loading="lazy"
                             onclick="openPreview('<?php echo apiUrl('preview', $file['path']); ?>', '<?php echo htmlspecialchars($file['name']); ?>', 'image')">
                    <?php else: ?>
                        <i class="<?php echo $file['icon']; ?> text-<?php echo $file['color']; ?>"></i>
                    <?php endif; ?>
                </div>
                
                <div class="file-info">
                    <h6 class="file-name"><?php echo htmlspecialchars($file['name']); ?></h6>
                    <div class="file-meta">
                        <span><?php echo format_file_size($file['size']); ?></span>
                        <span><?php echo date('M j, Y', $file['modified']); ?></span>
                    </div>
                </div>
                
                <div class="file-actions">
                    <a href="<?php echo apiUrl('download', $file['path']); ?>" 
                       class="btn-action btn-download" 
                       title="Download">
                        <i class="fas fa-download"></i>
                    </a>
                    
                    <?php if (in_array($file['mime'], ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'application/pdf'])): ?>
                    <button class="btn-action btn-preview" 
                            title="Preview"
                            onclick="openPreview('<?php echo apiUrl('preview', $file['path']); ?>', '<?php echo htmlspecialchars($file['name']); ?>', '<?php echo strpos($file['mime'], 'image/') === 0 ? 'image' : (strpos($file['mime'], 'video/') === 0 ? 'video' : 'pdf'); ?>')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <?php endif; ?>
                    
                    <?php if (in_array('write', $userPermissions)): ?>
                    <button class="btn-action btn-rename" 
                            title="Rename"
                            onclick="renameFile('<?php echo base64_encode($file['path']); ?>', '<?php echo htmlspecialchars($file['name']); ?>')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <?php endif; ?>
                    
                    <?php if (in_array('delete', $userPermissions)): ?>
                    <button class="btn-action btn-delete" 
                            title="Delete"
                            onclick="deleteFile('<?php echo base64_encode($file['path']); ?>', '<?php echo htmlspecialchars($file['name']); ?>')">
                        <i class="fas fa-trash"></i>
                    </button>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>

            <?php if (count($files) === 0): ?>
            <div class="col-12">
                <div class="empty-state">
                    <i class="fas fa-folder-open"></i>
                    <h5>No files found</h5>
                    <p><?php echo in_array('write', $userPermissions) ? 'Upload some files to get started' : 'This folder is empty'; ?></p>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Modals -->
    
    <!-- New Folder Modal -->
    <?php if (in_array('write', $userPermissions)): ?>
    <div class="modal fade" id="folderModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-folder-plus me-2"></i>
                        Create New Folder
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="folderForm">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="folder_name" class="form-label">Folder Name</label>
                            <input type="text" class="form-control" 
                                   id="folder_name" name="folder_name" 
                                   placeholder="Enter folder name" required>
                            <div class="form-text text-muted">
                                Only letters, numbers, spaces, hyphens and underscores are allowed.
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            Cancel
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus me-2"></i>
                            Create
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Settings Modal -->
    <?php if (in_array('settings', $userPermissions)): ?>
    <div class="modal fade" id="settingsModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-cog me-2"></i>
                        System Settings
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="settings-panel">
                        <h5>General Settings</h5>
                        <div class="setting-item">
                            <label class="setting-label">Admin Password</label>
                            <input type="password" class="form-control" id="admin_password" 
                                   value="<?php echo htmlspecialchars($settings['admin_password']); ?>">
                        </div>
                        <div class="setting-item">
                            <label class="setting-label">Maximum Upload Size (bytes)</label>
                            <input type="number" class="form-control" id="max_upload_bytes" 
                                   value="<?php echo $settings['max_upload_bytes']; ?>">
                            <small class="text-muted">Current: <?php echo format_file_size($settings['max_upload_bytes']); ?></small>
                        </div>
                        <div class="setting-item">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="show_hidden_files" 
                                       <?php echo $settings['show_hidden_files'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="show_hidden_files">
                                    Show Hidden Files
                                </label>
                            </div>
                        </div>
                        <div class="setting-item">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="enable_thumbnails" 
                                       <?php echo $settings['enable_thumbnails'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="enable_thumbnails">
                                    Enable Thumbnails
                                </label>
                            </div>
                        </div>
                    </div>

                    <div class="settings-panel">
                        <h5>User Profiles</h5>
                        <?php foreach ($profiles as $profileKey => $profileData): ?>
                        <div class="profile-settings mb-3 p-3 border rounded">
                            <h6><?php echo htmlspecialchars($profileData['name']); ?> (<?php echo $profileKey; ?>)</h6>
                            <div class="row">
                                <div class="col-md-6">
                                    <label class="setting-label">Upload Limit (bytes)</label>
                                    <input type="number" class="form-control profile-upload-limit" 
                                           data-profile="<?php echo $profileKey; ?>"
                                           value="<?php echo $profileData['upload_limit']; ?>">
                                    <small class="text-muted">
                                        <?php echo $profileData['upload_limit'] > 0 ? format_file_size($profileData['upload_limit']) : 'Unlimited'; ?>
                                    </small>
                                </div>
                                <div class="col-md-6">
                                    <label class="setting-label">Permissions</label>
                                    <div>
                                        <?php 
                                        $allPermissions = ['read', 'write', 'delete', 'settings'];
                                        foreach ($allPermissions as $perm): 
                                        ?>
                                        <div class="form-check form-check-inline">
                                            <input class="form-check-input profile-permission" type="checkbox" 
                                                   data-profile="<?php echo $profileKey; ?>" 
                                                   data-permission="<?php echo $perm; ?>"
                                                   <?php echo in_array($perm, $profileData['permissions']) ? 'checked' : ''; ?>>
                                            <label class="form-check-label"><?php echo ucfirst($perm); ?></label>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                        Cancel
                    </button>
                    <button type="button" class="btn btn-primary" onclick="saveSettings()">
                        <i class="fas fa-save me-2"></i>
                        Save Settings
                    </button>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Preview Modal -->
    <div class="modal fade" id="previewModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="previewTitle">
                        <i class="fas fa-eye me-2"></i>
                        Preview
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body text-center p-0" id="previewBody">
                    <!-- Preview content will be loaded here -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                        Close
                    </button>
                    <a href="#" class="btn btn-primary" id="downloadFromPreview" download>
                        <i class="fas fa-download me-2"></i>
                        Download
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <?php if (in_array('write', $userPermissions)): ?>
    <div class="modal fade" id="renameModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="fas fa-edit me-2"></i>
                        Rename File
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form id="renameForm">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="new_name" class="form-label">New Name</label>
                            <input type="text" class="form-control" 
                                   id="new_name" name="new_name" required>
                            <div class="form-text text-muted">
                                Keep the file extension to maintain file type.
                            </div>
                        </div>
                        <input type="hidden" id="rename_path" name="path">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            Cancel
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>
                            Rename
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Bulk Actions -->
    <?php if (in_array('delete', $userPermissions)): ?>
    <div class="bulk-actions" id="bulkActions">
        <div class="selection-info">
            <span id="selectedCount">0</span> files selected
        </div>
        <div class="d-flex gap-2">
            <button class="btn btn-sm btn-danger" onclick="deleteSelected()">
                <i class="fas fa-trash me-1"></i>
                Delete
            </button>
            <button class="btn btn-sm btn-secondary" onclick="deselectAll()">
                <i class="fas fa-times me-1"></i>
                Deselect
            </button>
        </div>
    </div>
    <?php endif; ?>

    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- Context Menu -->
    <div class="context-menu d-none" id="contextMenu">
        <div class="context-item" onclick="contextAction('download')">
            <i class="fas fa-download"></i>
            Download
        </div>
        <div class="context-item" onclick="contextAction('preview')">
            <i class="fas fa-eye"></i>
            Preview
        </div>
        <?php if (in_array('write', $userPermissions)): ?>
        <div class="context-item" onclick="contextAction('rename')">
            <i class="fas fa-edit"></i>
            Rename
        </div>
        <?php endif; ?>
        <?php if (in_array('delete', $userPermissions)): ?>
        <div class="context-item text-danger" onclick="contextAction('delete')">
            <i class="fas fa-trash"></i>
            Delete
        </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedFiles = new Set();
        let currentContextFile = null;
        const userPermissions = <?php echo json_encode($userPermissions); ?>;

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            setupDragAndDrop();
            setupFileUpload();
            setupContextMenu();
            initializeTooltips();
        });

        // Settings management
        function saveSettings() {
            const settings = {
                admin_password: document.getElementById('admin_password').value,
                max_upload_bytes: parseInt(document.getElementById('max_upload_bytes').value),
                show_hidden_files: document.getElementById('show_hidden_files').checked,
                enable_thumbnails: document.getElementById('enable_thumbnails').checked,
                allowed_mime_types: <?php echo json_encode($ALLOWED_MIME_TYPES); ?>
            };

            const profiles = {};
            document.querySelectorAll('.profile-settings').forEach(profileDiv => {
                const profileKey = profileDiv.querySelector('.profile-upload-limit').dataset.profile;
                const uploadLimit = parseInt(profileDiv.querySelector('.profile-upload-limit').value) || 0;
                const permissions = [];
                
                profileDiv.querySelectorAll('.profile-permission:checked').forEach(checkbox => {
                    permissions.push(checkbox.dataset.permission);
                });

                profiles[profileKey] = {
                    name: profileDiv.querySelector('h6').textContent.split(' (')[0],
                    upload_limit: uploadLimit,
                    permissions: permissions,
                    allowed_extensions: '*'
                };
            });

            Promise.all([
                fetch('?api=settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ settings: settings })
                }),
                fetch('?api=settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ profiles: profiles })
                })
            ])
            .then(responses => Promise.all(responses.map(r => r.json())))
            .then(results => {
                if (results.every(r => r.success)) {
                    showToast('success', 'Settings saved successfully! Page will reload.');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showToast('danger', 'Failed to save some settings');
                }
                bootstrap.Modal.getInstance(document.getElementById('settingsModal')).hide();
            })
            .catch(error => {
                showToast('danger', 'Error saving settings: ' + error.message);
            });
        }

        // Drag and Drop functionality
        function setupDragAndDrop() {
            if (!userPermissions.includes('write')) return;
            
            const dropZone = document.getElementById('dropZone');
            if (!dropZone) return;
            
            let dragCounter = 0;

            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, preventDefaults, false);
                document.body.addEventListener(eventName, preventDefaults, false);
            });

            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, highlight, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, unhighlight, false);
            });

            dropZone.addEventListener('drop', handleDrop, false);

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            function highlight(e) {
                dropZone.classList.add('dragover');
            }

            function unhighlight(e) {
                dropZone.classList.remove('dragover');
            }

            function handleDrop(e) {
                const files = e.dataTransfer.files;
                handleFiles(files);
            }
        }

        // File upload setup
        function setupFileUpload() {
            const fileInput = document.getElementById('uploadInput');
            const uploadForm = document.getElementById('uploadForm');
            
            if (!fileInput || !userPermissions.includes('write')) return;

            fileInput.addEventListener('change', function() {
                handleFiles(this.files);
            });

            if (uploadForm) {
                uploadForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    uploadFiles();
                });
            }
        }

        // Handle file selection
        function handleFiles(files) {
            if (!files || files.length === 0) return;

            const fileInput = document.getElementById('uploadInput');
            if (fileInput) {
                fileInput.files = files;
            }
            
            showToast('success', `${files.length} file(s) selected for upload`);
            
            // Auto upload after short delay
            setTimeout(() => {
                uploadFiles();
            }, 1000);
        }

        // Upload files
        function uploadFiles() {
            const fileInput = document.getElementById('uploadInput');
            if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
                showToast('warning', 'Please select files first');
                return;
            }

            const files = fileInput.files;
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files[]', files[i]);
            }
            formData.append('ajax', '1');

            const progressBar = document.querySelector('#uploadProgress .progress-bar');
            const uploadProgress = document.getElementById('uploadProgress');
            if (uploadProgress) uploadProgress.classList.remove('d-none');

            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (uploadProgress) uploadProgress.classList.add('d-none');
                
                if (data.results) {
                    const successCount = data.results.filter(r => r.success).length;
                    const errorCount = data.results.filter(r => !r.success).length;
                    
                    if (successCount > 0) {
                        showToast('success', `${successCount} file(s) uploaded successfully!`);
                        setTimeout(() => location.reload(), 1500);
                    }
                    
                    if (errorCount > 0) {
                        const errors = data.results.filter(r => !r.success);
                        showToast('danger', `${errorCount} file(s) failed: ${errors[0].error}`);
                    }
                }
            })
            .catch(error => {
                if (uploadProgress) uploadProgress.classList.add('d-none');
                showToast('danger', 'Upload failed: ' + error.message);
            });

            // Simulate progress
            if (progressBar) {
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += Math.random() * 15;
                    if (progress > 90) progress = 90;
                    progressBar.style.width = progress + '%';
                }, 200);

                setTimeout(() => {
                    clearInterval(progressInterval);
                    progressBar.style.width = '100%';
                }, 3000);
            }
        }

        // Create folder
        const folderForm = document.getElementById('folderForm');
        if (folderForm) {
            folderForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                formData.append('action', 'create_folder');
                formData.append('ajax', '1');
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showToast('success', data.message);
                        bootstrap.Modal.getInstance(document.getElementById('folderModal')).hide();
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        showToast('danger', data.error || 'Failed to create folder');
                    }
                })
                .catch(error => {
                    showToast('danger', 'Error: ' + error.message);
                });
            });
        }

        // File operations
        function deleteFile(encodedPath, filename) {
            if (!confirm(`Are you sure you want to delete "${filename}"?`)) return;

            fetch('?api=delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    path: encodedPath
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('success', data.message);
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showToast('danger', data.error || 'Delete failed');
                }
            })
            .catch(error => {
                showToast('danger', 'Error: ' + error.message);
            });
        }

        function renameFile(encodedPath, currentName) {
            document.getElementById('new_name').value = currentName;
            document.getElementById('rename_path').value = encodedPath;
            new bootstrap.Modal(document.getElementById('renameModal')).show();
        }

        const renameForm = document.getElementById('renameForm');
        if (renameForm) {
            renameForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const data = {
                    oldPath: formData.get('path'),
                    newName: formData.get('new_name')
                };

                fetch('?api=rename', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showToast('success', data.message);
                        bootstrap.Modal.getInstance(document.getElementById('renameModal')).hide();
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        showToast('danger', data.error || 'Rename failed');
                    }
                })
                .catch(error => {
                    showToast('danger', 'Error: ' + error.message);
                });
            });
        }

        // Preview functionality
        function openPreview(url, filename, type) {
            document.getElementById('previewTitle').innerHTML = '<i class="fas fa-eye me-2"></i>' + filename;
            document.getElementById('downloadFromPreview').href = url.replace('api=preview', 'api=download');
            
            let content = '';
            
            if (type === 'image') {
                content = `<img src="${url}" class="img-fluid" style="max-height: 70vh; border-radius: 8px;">`;
            } else if (type === 'video') {
                content = `
                    <video controls style="max-width: 100%; max-height: 70vh; border-radius: 8px;">
                        <source src="${url}" type="video/mp4">
                        Your browser does not support video playback.
                    </video>
                `;
            } else if (type === 'pdf') {
                content = `<iframe src="${url}" style="width: 100%; height: 70vh; border: none; border-radius: 8px;"></iframe>`;
            }
            
            document.getElementById('previewBody').innerHTML = content;
            new bootstrap.Modal(document.getElementById('previewModal')).show();
        }

        // Search functionality
        function searchFiles() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const fileCards = document.querySelectorAll('.file-card');
            
            fileCards.forEach(card => {
                const filename = card.getAttribute('data-name');
                if (filename && filename.includes(query)) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }

        // Selection functionality
        function updateSelection() {
            const checkboxes = document.querySelectorAll('.file-select');
            selectedFiles.clear();
            
            checkboxes.forEach(checkbox => {
                if (checkbox.checked) {
                    const card = checkbox.closest('.file-card');
                    if (card) {
                        card.classList.add('selected');
                        selectedFiles.add(card);
                    }
                } else {
                    const card = checkbox.closest('.file-card');
                    if (card) {
                        card.classList.remove('selected');
                    }
                }
            });
            
            const selectedCountEl = document.getElementById('selectedCount');
            if (selectedCountEl) {
                selectedCountEl.textContent = selectedFiles.size;
            }
            
            const bulkActions = document.getElementById('bulkActions');
            if (bulkActions) {
                if (selectedFiles.size > 0) {
                    bulkActions.classList.add('show');
                } else {
                    bulkActions.classList.remove('show');
                }
            }
        }

        function selectAll() {
            const checkboxes = document.querySelectorAll('.file-select');
            checkboxes.forEach(checkbox => {
                checkbox.checked = true;
            });
            updateSelection();
        }

        function deselectAll() {
            const checkboxes = document.querySelectorAll('.file-select');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            updateSelection();
        }

        function deleteSelected() {
            if (selectedFiles.size === 0) return;
            
            if (!confirm(`Are you sure you want to delete ${selectedFiles.size} selected file(s)?`)) return;
            
            const promises = [];
            selectedFiles.forEach(card => {
                const deleteBtn = card.querySelector('.btn-delete');
                if (deleteBtn) {
                    const onclick = deleteBtn.getAttribute('onclick');
                    const match = onclick.match(/'([^']+)'/);
                    if (match) {
                        const encodedPath = match[1];
                        promises.push(
                            fetch('?api=delete', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ path: encodedPath })
                            })
                        );
                    }
                }
            });
            
            Promise.all(promises)
                .then(() => {
                    showToast('success', `${selectedFiles.size} file(s) deleted successfully`);
                    setTimeout(() => location.reload(), 1000);
                })
                .catch(error => {
                    showToast('danger', 'Some files could not be deleted');
                });
        }

        // Context menu
        function setupContextMenu() {
            const contextMenu = document.getElementById('contextMenu');
            
            document.querySelectorAll('.file-card').forEach(card => {
                card.addEventListener('contextmenu', function(e) {
                    e.preventDefault();
                    currentContextFile = this;
                    
                    contextMenu.style.left = e.pageX + 'px';
                    contextMenu.style.top = e.pageY + 'px';
                    contextMenu.classList.remove('d-none');
                });
            });
            
            document.addEventListener('click', function() {
                if (contextMenu) {
                    contextMenu.classList.add('d-none');
                }
            });
        }

        function contextAction(action) {
            if (!currentContextFile) return;
            
            const contextMenu = document.getElementById('contextMenu');
            if (contextMenu) contextMenu.classList.add('d-none');
            
            switch (action) {
                case 'download':
                    const downloadBtn = currentContextFile.querySelector('.btn-download');
                    if (downloadBtn) downloadBtn.click();
                    break;
                    
                case 'preview':
                    const previewBtn = currentContextFile.querySelector('.btn-preview');
                    if (previewBtn) previewBtn.click();
                    break;
                    
                case 'rename':
                    const renameBtn = currentContextFile.querySelector('.btn-rename');
                    if (renameBtn) renameBtn.click();
                    break;
                    
                case 'delete':
                    const deleteBtn = currentContextFile.querySelector('.btn-delete');
                    if (deleteBtn) deleteBtn.click();
                    break;
            }
            
            currentContextFile = null;
        }

        // Toast notifications
        function showToast(type, message) {
            const toastContainer = document.getElementById('toastContainer');
            if (!toastContainer) return;
            
            const toastId = 'toast-' + Date.now();
            
            const iconMap = {
                success: 'check-circle',
                danger: 'exclamation-triangle',
                warning: 'exclamation-circle',
                info: 'info-circle'
            };
            
            const toast = document.createElement('div');
            toast.id = toastId;
            toast.className = `toast show`;
            toast.innerHTML = `
                <div class="toast-header">
                    <i class="fas fa-${iconMap[type]} text-${type} me-2"></i>
                    <strong class="me-auto">Notification</strong>
                    <button type="button" class="btn-close" onclick="hideToast('${toastId}')"></button>
                </div>
                <div class="toast-body">
                    ${message}
                </div>
            `;
            
            toastContainer.appendChild(toast);
            
            // Auto hide after 5 seconds
            setTimeout(() => {
                hideToast(toastId);
            }, 5000);
        }

        function hideToast(toastId) {
            const toast = document.getElementById(toastId);
            if (toast) {
                toast.classList.remove('show');
                setTimeout(() => {
                    toast.remove();
                }, 300);
            }
        }

        // Mobile sidebar toggle
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            if (sidebar) {
                sidebar.classList.toggle('show');
            }
        }

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(e) {
            if (window.innerWidth <= 768) {
                const sidebar = document.getElementById('sidebar');
                if (sidebar && !e.target.closest('#sidebar, .mobile-toggle')) {
                    sidebar.classList.remove('show');
                }
            }
        });

        // Initialize tooltips
        function initializeTooltips() {
            // Simple tooltip implementation since bootstrap tooltips need initialization
            const tooltipElements = document.querySelectorAll('[title]');
            tooltipElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    const tooltip = document.createElement('div');
                    tooltip.className = 'custom-tooltip';
                    tooltip.textContent = this.getAttribute('title');
                    tooltip.style.cssText = `
                        position: fixed;
                        background: var(--bg-secondary);
                        color: var(--text-primary);
                        padding: 0.5rem;
                        border-radius: 6px;
                        font-size: 0.75rem;
                        z-index: 10000;
                        pointer-events: none;
                        border: 1px solid var(--border);
                    `;
                    document.body.appendChild(tooltip);
                    
                    const rect = this.getBoundingClientRect();
                    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
                    tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
                    
                    this._tooltip = tooltip;
                });
                
                element.addEventListener('mouseleave', function() {
                    if (this._tooltip) {
                        this._tooltip.remove();
                        this._tooltip = null;
                    }
                });
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // ESC to close modals and sidebar
            if (e.key === 'Escape') {
                const sidebar = document.getElementById('sidebar');
                if (sidebar) sidebar.classList.remove('show');
                
                const contextMenu = document.getElementById('contextMenu');
                if (contextMenu) contextMenu.classList.add('d-none');
            }
            
            // Ctrl+U for upload (only if user has write permission)
            if (e.ctrlKey && e.key === 'u' && userPermissions.includes('write')) {
                e.preventDefault();
                const uploadInput = document.getElementById('uploadInput');
                if (uploadInput) uploadInput.click();
            }
            
            // Ctrl+N for new folder (only if user has write permission)
            if (e.ctrlKey && e.key === 'n' && userPermissions.includes('write')) {
                e.preventDefault();
                const folderModal = document.getElementById('folderModal');
                if (folderModal) {
                    new bootstrap.Modal(folderModal).show();
                }
            }
            
            // Ctrl+A for select all (only if user has delete permission)
            if (e.ctrlKey && e.key === 'a' && e.target.tagName !== 'INPUT' && userPermissions.includes('delete')) {
                e.preventDefault();
                selectAll();
            }
            
            // Delete key for selected files (only if user has delete permission)
            if (e.key === 'Delete' && selectedFiles.size > 0 && userPermissions.includes('delete')) {
                deleteSelected();
            }
        });

        // Performance: Lazy loading for images
        const imageObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    if (img.dataset.src) {
                        img.src = img.dataset.src;
                        img.removeAttribute('data-src');
                        imageObserver.unobserve(img);
                    }
                }
            });
        });

        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });

        // Auto-refresh notifications for cloud sync (optional)
        let lastFileCount = <?php echo count($files); ?>;
        
        function checkForUpdates() {
            fetch(window.location.href + '&check=1')
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const newFileCount = doc.querySelectorAll('.file-card').length;
                    
                    if (newFileCount !== lastFileCount) {
                        showToast('info', 'Files updated. Click refresh to see changes.');
                        lastFileCount = newFileCount;
                    }
                })
                .catch(() => {
                    // Silently fail - don't spam user with network errors
                });
        }

        // Check for updates every 30 seconds (cloud-ready feature)
        setInterval(checkForUpdates, 30000);

        // Console information for developers
        console.log('🚀 Advanced Cloud File Manager loaded successfully!');
        console.log('💡 Keyboard Shortcuts:');
        if (userPermissions.includes('write')) {
            console.log('   Ctrl+U: Upload files');
            console.log('   Ctrl+N: New folder');
        }
        if (userPermissions.includes('delete')) {
            console.log('   Ctrl+A: Select all');
            console.log('   Delete: Delete selected');
        }
        console.log('   ESC: Close modals/sidebar');
        console.log('👤 Current permissions:', userPermissions);
    </script>
</body>
</html>
