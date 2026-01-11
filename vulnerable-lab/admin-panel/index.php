<?php
/**
 * Vulnerable Admin Panel
 * Contains: Auth bypass, SQLi, File upload, LFI, Command injection
 */

// Vulnerable: Hardcoded credentials
$ADMIN_USER = 'admin';
$ADMIN_PASS = 'admin123';

// Vulnerable: Session without secure flags
session_start();

// Vulnerable: SQL Injection in login
function authenticate($username, $password) {
    global $ADMIN_USER, $ADMIN_PASS;
    
    // Vulnerable: String comparison bypass with type juggling
    if ($username == $ADMIN_USER && $password == $ADMIN_PASS) {
        return true;
    }
    
    // Vulnerable: SQL Injection (simulated)
    $query = "SELECT * FROM admins WHERE username='$username' AND password='$password'";
    
    // For demo, check for SQLi patterns
    if (strpos($username, "'") !== false || strpos($password, "'") !== false) {
        // SQLi detected - "authenticate" anyway
        return true;
    }
    
    return false;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (authenticate($username, $password)) {
        $_SESSION['authenticated'] = true;
        $_SESSION['user'] = $username;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Vulnerable: Command execution
if (isset($_GET['cmd']) && isset($_SESSION['authenticated'])) {
    $output = shell_exec($_GET['cmd']);
}

// Vulnerable: File inclusion
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // Vulnerable: No sanitization - LFI possible
}

// Vulnerable: File upload
if (isset($_FILES['upload']) && isset($_SESSION['authenticated'])) {
    $target = 'uploads/' . basename($_FILES['upload']['name']);
    // Vulnerable: No file type validation
    move_uploaded_file($_FILES['upload']['tmp_name'], $target);
    $upload_message = "File uploaded to: $target";
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Internal Use Only</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 800px; margin: 0 auto; }
        .login-form { background: #16213e; padding: 30px; border-radius: 10px; }
        input, button { padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; }
        button { background: #e94560; color: white; border: none; cursor: pointer; }
        button:hover { background: #ff6b6b; }
        .panel { background: #16213e; padding: 20px; margin-top: 20px; border-radius: 10px; }
        .output { background: #0f0f23; padding: 15px; font-family: monospace; white-space: pre-wrap; }
        .warning { color: #e94560; }
        a { color: #4ea8de; }
        h1 { color: #e94560; }
        .nav { background: #0f3460; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
        .nav a { margin-right: 20px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Internal Admin Panel</h1>
        
        <?php if (!isset($_SESSION['authenticated'])): ?>
        
        <div class="login-form">
            <h2>Login Required</h2>
            <form method="POST">
                <input type="hidden" name="action" value="login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p class="warning">⚠️ Authorized personnel only</p>
        </div>
        
        <?php else: ?>
        
        <div class="nav">
            <a href="?">Dashboard</a>
            <a href="?page=users">Users</a>
            <a href="?page=logs">Logs</a>
            <a href="?page=config">Config</a>
            <a href="?page=../../../etc/passwd">System</a>
            <a href="?logout=1">Logout</a>
        </div>
        
        <div class="panel">
            <h2>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?>!</h2>
            
            <!-- Command Execution Panel -->
            <h3>🖥️ System Command</h3>
            <form method="GET">
                <input type="text" name="cmd" placeholder="Enter command (e.g., whoami, id, ls -la)" value="<?php echo htmlspecialchars($_GET['cmd'] ?? ''); ?>">
                <button type="submit">Execute</button>
            </form>
            
            <?php if (isset($output)): ?>
            <div class="output"><?php echo htmlspecialchars($output); ?></div>
            <?php endif; ?>
            
            <!-- File Upload Panel -->
            <h3>📁 File Upload</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="upload">
                <button type="submit">Upload</button>
            </form>
            <?php if (isset($upload_message)): ?>
            <p style="color: #4ea8de;"><?php echo htmlspecialchars($upload_message); ?></p>
            <?php endif; ?>
            
            <!-- File Viewer -->
            <?php if (isset($_GET['page'])): ?>
            <h3>📄 File Contents: <?php echo htmlspecialchars($_GET['page']); ?></h3>
            <div class="output">
                <?php 
                // Vulnerable: LFI
                @include($_GET['page'] . '.php');
                // Also try to read the file directly
                $content = @file_get_contents($_GET['page']);
                if ($content) echo htmlspecialchars($content);
                ?>
            </div>
            <?php endif; ?>
            
            <!-- System Info -->
            <h3>ℹ️ System Information</h3>
            <div class="output">
Server: <?php echo php_uname(); ?>

PHP Version: <?php echo phpversion(); ?>

Document Root: <?php echo $_SERVER['DOCUMENT_ROOT']; ?>

Current User: <?php echo get_current_user(); ?>

Environment:
<?php 
foreach ($_ENV as $key => $value) {
    echo "$key = $value\n";
}
?>
            </div>
        </div>
        
        <?php endif; ?>
        
        <p style="margin-top: 20px; font-size: 12px; color: #666;">
            Internal Admin Panel v1.0 | <span class="warning">For authorized use only</span>
        </p>
    </div>
</body>
</html>
