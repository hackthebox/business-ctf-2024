<?php

error_reporting(-1);

if (!isset( $_SERVER['argv'], $_SERVER['argc'] ) || !$_SERVER['argc']) {
    die("This script must be run from the command line!");
}

function passthruOrFail($command) {
    passthru($command, $status);
    if ($status) {
        exit($status);
    }
}

function isConfig($probableConfig) {
    if (!$probableConfig) {
        return null;
    }
    if (is_dir($probableConfig)) {
        return isConfig($probableConfig.\DIRECTORY_SEPARATOR.'config.xml');
    }

    if (file_exists($probableConfig)) {
        return $probableConfig;
    }
    if (file_exists($probableConfig.'.xml')) {
        return $probableConfig.'.xml';
    }
    return null;
};

function getConfig($name) {

    $configFilename = isConfig(getCommandLineValue("--config", "-c"));

    if ($configFilename) {
        $dbConfig = new DOMDocument();
        $dbConfig->load($configFilename);

        $var = new DOMXPath($dbConfig);
        foreach ($var->query('/config/db[@name="'.$name.'"]') as $var) {
            return $var->getAttribute('value');
        }
        return null;
    }
    return null;
}

function getCommandLineValue($longOption, $shortOption) {
    $argv = $_SERVER['argv'] ?? [];

    $longIndex = array_search($longOption, $argv);
    $shortIndex = array_search($shortOption, $argv);
    $index = false;
    $option = '';

    if ($longIndex !== false) {
        $index = $longIndex;
        $option = $argv[$longIndex + 1] ?? null;
    } elseif ($shortIndex !== false) {
        $index = $shortIndex;
        $option = $argv[$shortIndex + 1] ?? null;
    }

    return $option;
}

function generateFilename() {
    $timestamp = date("Ymd_His");
    $random = bin2hex(random_bytes(4));
    $filename = "backup_$timestamp" . "_$random.sql";
    return $filename;
}

function backup($filename, $username, $password, $database) {
    $backupdir = "/tmp/backup/";
    passthruOrFail("mysqldump -u$username -p$password $database > $backupdir$filename");
}

function import($filename, $username, $password, $database) {
    passthruOrFail("mysql -u$username -p$password $database < $filename");
}

function healthCheck() {
    $url = 'http://localhost:80/info';

    $headers = get_headers($url);

    $responseCode = intval(substr($headers[0], 9, 3));

    if ($responseCode === 200) {
        echo "[+] Daijobu\n";
    } else {
        echo "[-] Not Daijobu :(\n";
    }
}

$username = getConfig("username");
$password = getConfig("password");
$database = getConfig("database");

$mode = getCommandLineValue("--mode", "-m");

if($mode) {
    switch ($mode) {
        case 'import':
            $filename = getCommandLineValue("--filename", "-f");
            if(file_exists($filename)) {
                import($filename, $username, $password, $database);
            } else {
                die("No file imported!");
            }
            break;
        case 'backup':
            backup(generateFilename(), $username, $password, $database);
            break;
        case 'healthcheck':
            healthcheck();
            break;
        default:
            die("Unknown mode specified.");
            break;
        }
}
?>