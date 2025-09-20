# Preface

### So I decided to try this AI code bullshit. After about 3 hours of fucking around, going backward and forward with more conversation than I have with humans every day, this is the result. I probably wrote about an 8th of the actual code. I do like how clean it is through, thats refreshing. I honestly don't know how anyone who doesn't know how to write code can produce anything really worth while with these tools because I had to read everything it generated, understand it and instruct it how to do things in a way that would work. Without that knowledge it would have produced a turd 💩 for sure.

Anyway, here it is!

Disable your auto index junk in your web server, and ensure that your web browser (or the php-fpm process, if different) has access to read/write from the current directory, then send it.

I made it go next level on security, and its supposed to have all the knowledge of the internet, so one would assume its as safe as can be. Seemed fine to me.

Here's a quick install command. From the directory you want to share files from:

```
curl -o index.php https://raw.githubusercontent.com/JoshFinlayAU/BetterIndex/main/betterindex.php
```

I trialed Cursor, and a few others, and settled on Windsurf Cascade using Claude Sonnet 4. It was the only one with a decent UI/integration that didn't produce as much bullshit.

Here is the README file that the thing spewed words at too:

---

# BetterIndex - Advanced PHP File Manager

A powerful, single-file directory browser and file management solution with authentication, file operations, and trash functionality. Perfect for secure file sharing and management from any web server.

## Quick Start

The simplest way to use this is to rename the file to `index.php` and drop it into any folder you want to manage:

```bash
# Rename and place in your target directory
mv file-manager.php /path/to/your/files/index.php
```

Now when someone visits that directory in a web browser, they'll see a secure, feature-rich file management interface.

## Features

### Core Functionality
- **Browse directories** - Navigate through folders with breadcrumb navigation and refresh button
- **Download files** - Click any file to download it instantly with activity logging
- **Mobile responsive** - Works great on phones and tablets with touch-friendly interface
- **Security focused** - Built-in path traversal protection, CSRF validation, and file type restrictions

### Authentication & Security
- **User authentication** - Secure login system with SQLite database
- **Session management** - Automatic session regeneration and timeout protection
- **Login attempt limiting** - Configurable lockout after failed attempts
- **Remember me functionality** - Optional persistent login sessions
- **Activity logging** - Comprehensive audit trail of all file operations
- **CSRF protection** - Token-based request validation for all operations

### File Operations (Admin Only)
- **File upload** - Drag-and-drop or click to upload with progress indication
- **Create folders** - Organize files with new directory creation
- **Delete files/folders** - Move items to trash with confirmation dialogs
- **Rename files/folders** - In-place renaming with validation
- **Trash management** - Comprehensive trash system with restore functionality

### Advanced Trash System
- **Trash dialog** - View all deleted files and folders in one place
- **Individual restore** - Restore specific files with visual feedback
- **Restore all** - Bulk restore operation for multiple items
- **Empty trash** - Permanent deletion with detailed reporting
- **Folder support** - Full support for deleted directories and their contents
- **Smart notifications** - Toast notifications for all operations

### Interface Options
- **Multiple view modes** - Switch between grid, list, and compact views with localStorage persistence
- **Theme system** - Multiple color themes (light, dark, blue, green, purple) with custom CSS variables
- **File type icons** - Visual indicators for different file types and folders
- **Search functionality** - Real-time file filtering
- **Responsive design** - Optimized for desktop, tablet, and mobile devices

### Smart Filtering & Display
- **Hidden files** - Dotfiles (`.htaccess`, `.env`, etc.) are hidden by default
- **Self-hiding** - The script automatically hides itself from listings
- **File type restrictions** - Configurable allowed extensions for uploads and downloads
- **Size formatting** - Human-readable file sizes with proper units
- **Date formatting** - Localized date/time display for file modifications

## Configurable Options

Open the PHP file and modify these settings at the top (if you want to, however defaults usually work fine too):

### Basic Settings
```php
// Core Configuration
$base_path = __DIR__;  // Directory to serve files from
$max_file_size = 100 * 1024 * 1024;  // 100MB download/upload limit
$page_title = 'Index of /';  // Browser title prefix
$default_theme = 'light';  // 'light', 'dark', 'blue', 'green', 'purple'
$default_view = 'list';    // 'grid', 'list', or 'compact'
$hide_dotfiles = true;     // Hide files starting with '.'
```

### Security Configuration
```php
// Authentication
$auth_enabled = true;  // Enable/disable login system
$auth_db_path = __DIR__ . '/.betterindex_users.db';  // User database location
$login_attempts_limit = 5;  // Max failed attempts before lockout
$lockout_duration = 300;    // Lockout time in seconds (5 minutes)
$remember_me_duration = 2592000;  // Remember me duration (30 days)
$csrf_validation = true;    // Enable CSRF protection

// File Operations Security
$dangerous_extensions = ['php', 'phtml', 'exe', 'bat', 'cmd', 'sh', 'py'];
$check_file_content = true;  // Scan uploaded files for dangerous content
$file_content_regex = '/<\?php|<script|javascript:|vbscript:/i';
```

### File Management
```php
// Trash and Operations
$trash_folder = $base_path . '/.betterindex_trash';  // Deleted files location
$max_upload_size = $max_file_size;  // Upload size limit
$allowed_upload_extensions = $allowed_extensions;  // Uploadable file types

// Activity Logging
$log_activity = true;  // Enable operation logging
$log_file_path = __DIR__ . '/.betterindex_activity.log';
$log_max_lines = 1000;  // Maximum log entries to keep

// Allowed file extensions
$allowed_extensions = [
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'zip', 'rar', '7z', 'tar', 'gz',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp',
    'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv',
    'html', 'css', 'js', 'json', 'xml', 'tbn'
];

// To allow ALL file types (use with extreme caution):
// $allowed_extensions = ['*'];
```

### Theme Customization
```php
// Custom color schemes - modify the $theme_config array
$theme_config = [
    'light' => [
        'accent_color' => '#5a2ca0',    // Primary accent color
        'accent_hover' => '#7950f2',    // Hover state color
        // ... other color variables
    ],
    // Add custom themes here
];
```

## User Management

### Initial Setup
On first run, BetterIndex will automatically create the user database - IF you enabled authentication.

The initial user will be setup as follows:

Username: `admin`
Password: `admin123` - change it!

### Managing Users (Admin Only)
- **View users** - Access user management from the admin panel
- **Create users** - Add new users with different permission levels
- **Delete users** - Remove user accounts (cannot delete yourself)
- **Activity monitoring** - View comprehensive logs of all user actions

### User Roles
- **Admin** - Full access to all features including file operations and user management
- **User** - Read-only access for browsing and downloading files

## Common Use Cases

### Secure File Sharing Server
```bash
# Create a secure downloads folder with authentication
mkdir /var/www/secure-downloads
cp file-manager.php /var/www/secure-downloads/index.php

# Configure authentication in the file
# Set $auth_enabled = true
# Users must log in to access files
```

### Team File Management
```bash
# Perfect for team file collaboration
cp file-manager.php /var/www/team-files/index.php
# Admins can upload, organize, and manage files
# Team members can browse and download
```

### Media Gallery with Upload
```bash
# Photo/video sharing with upload capabilities
cp file-manager.php /var/www/media/index.php
# Set $default_view = 'grid' for best visual experience
# Admins can upload new media files
```

### Document Archive System
```bash
# Organized document storage with trash protection
cp file-manager.php /var/www/documents/index.php
# Set $default_view = 'list' for detailed file information
# Deleted files go to trash for recovery
```

## Security Features

BetterIndex includes comprehensive security measures:

### Authentication Security
- **Secure password hashing** - Uses PHP's `password_hash()` with strong algorithms
- **Session protection** - Automatic session regeneration and timeout handling
- **Login attempt limiting** - Configurable lockout after failed attempts
- **CSRF protection** - Token-based validation for all state-changing operations
- **Remember me security** - Secure persistent login with token rotation

### File Operation Security
- **Path validation** - Prevents directory traversal attacks (`../../../etc/passwd`)
- **File type filtering** - Configurable allowed extensions for uploads and downloads
- **Content scanning** - Optional scanning of uploaded files for dangerous code
- **Size limits** - Prevents uploading/downloading of extremely large files
- **Dangerous file blocking** - Automatic blocking of executable and script files

### System Security
- **Self-protection** - Hides itself from directory listings
- **Database security** - SQLite database with proper permissions
- **Activity logging** - Comprehensive audit trail of all operations
- **Input sanitization** - All user inputs are properly sanitized and validated

### Deployment Security
- Only deploy on servers you control
- Use HTTPS in production environments
- Regularly review activity logs
- Keep PHP and web server updated
- Consider additional firewall rules for admin access

## Advanced Features

### Trash System
- **Soft delete** - Files moved to trash instead of permanent deletion
- **Restore functionality** - Individual or bulk restore operations
- **Folder support** - Complete directory structures preserved in trash
- **Smart notifications** - Real-time feedback for all operations
- **Automatic cleanup** - Optional automatic trash emptying

### User Interface
- **Responsive design** - Works perfectly on desktop, tablet, and mobile
- **Multiple themes** - Light, dark, and color variants with CSS custom properties
- **View persistence** - User preferences saved in localStorage
- **Real-time search** - Instant file filtering as you type
- **Drag-and-drop** - Modern file upload interface

### Performance Features
- **Efficient directory scanning** - Optimized for large directories
- **Lazy loading** - Resources loaded only when needed
- **Caching headers** - Proper HTTP caching for static assets
- **Minimal dependencies** - Single file with no external requirements

## Customization Guide

### Branding
```php
// Change the application name
$page_title = 'Your Company Files';

// Update login page title
// Edit line ~1283: <h1>🔐 Your Brand</h1>

// Update main header
// Edit line ~3644: <span>📁</span> Your Brand
```

### Theme Customization
```php
// Add custom theme colors
$theme_config['custom'] = [
    'bg_primary' => '#your-color',
    'accent_color' => '#your-accent',
    // ... other properties
];
```

### File Icons
```php
// Customize file type icons in getFileIcon() function
$icons = [
    'pdf' => '📄',
    'zip' => '🗜️',
    'mp3' => '🎵',
    'custom' => '🎯',  // Add your own
];
```

### Custom File Filtering
```php
// Add custom rules in getDirectoryContents()
if (str_ends_with($file, '.backup')) continue;  // Hide backups
if (str_starts_with($file, 'temp_')) continue;  // Hide temp files
```

## System Requirements

### Server Requirements
- **PHP 7.4 or higher** (PHP 8.x recommended)
- **Web server** (Apache, Nginx, IIS, etc.)
- **SQLite support** (usually included with PHP)
- **File system permissions** for read/write operations

### Browser Compatibility
- Chrome/Chromium 60+
- Firefox 55+
- Safari 12+
- Edge 79+
- Mobile browsers (iOS Safari, Chrome Mobile)

### Recommended Server Configuration
```apache
# Apache .htaccess example
<Files ".betterindex_*">
    Order allow,deny
    Deny from all
</Files>

# Optional: Restrict admin access by IP
<Location "/admin">
    Order deny,allow
    Deny from all
    Allow from 192.168.1.0/24
</Location>
```

## Troubleshooting

### Authentication Issues
**Can't log in / "Invalid credentials"**
- Check username and password are correct
- Verify database file permissions (`.betterindex_users.db`)
- Check if account is locked due to failed attempts
- Ensure cookies are enabled in browser

**Session expires too quickly**
- Increase `session.gc_maxlifetime` in PHP configuration
- Check server time synchronization
- Verify session storage permissions

### File Operation Issues
**Upload fails**
- Check file size against `$max_upload_size` limit
- Verify file extension is in `$allowed_upload_extensions`
- Ensure target directory has write permissions
- Check PHP `upload_max_filesize` and `post_max_size` settings

**Files won't download**
- Verify file extension is in `$allowed_extensions`
- Check file permissions on server
- Ensure file exists and is readable

**Trash operations not working**
- Check trash folder permissions (`$trash_folder`)
- Verify sufficient disk space
- Ensure PHP can create directories

### Interface Issues
**Styling looks broken**
- Clear browser cache and reload
- Check browser console for JavaScript errors
- Verify entire PHP file was uploaded correctly
- Test in different browser

**Search not working**
- Check JavaScript is enabled
- Clear browser cache
- Verify no JavaScript errors in console

### Performance Issues
**Slow directory loading**
- Consider increasing PHP memory limit
- Check for very large directories (>1000 files)
- Verify adequate server resources
- Consider enabling PHP OPcache

## License & Support

This is open source software released under the MIT License. Use it however you want, modify it, share it. 

**No warranties or guarantees** - use at your own risk.

### Getting Help
- Check the configuration options at the top of the PHP file
- Review the troubleshooting section above
- Examine the activity log for error details
- Test with minimal configuration first

---

*BetterIndex - Making file management better, one directory at a time.*
