<?php
/*WebShell Scanner by 0x6ick - 6ickzone
 * Version: 1.2.3
 * https://t.me/Yungx6ick
 * SPDX-License-Identifier: WTFPL
 * "You just DO WHAT THE FUCK YOU WANT TO."
 * Respect the author.
 */

// ---- Router ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    $action = $_POST['action'];

    if ($action === 'scan') {
        $start = $_POST['path'] ?? '.';
        $maxDepth = intval($_POST['max_depth'] ?? 10);
        $rawWhitelist = explode("\n", trim($_POST['whitelist_patterns'] ?? ''));
        $whitelistPatterns = array_filter(array_map('trim', $rawWhitelist));

        // Get "recent scan" options
        $modified_recent = isset($_POST['modified_recent']) && $_POST['modified_recent'] === 'true';
        $modified_days = intval($_POST['modified_days'] ?? 7);

        $res = run_scan($start, $maxDepth, $whitelistPatterns, $modified_recent, $modified_days);
        
        // --- Write to log file ---
        $logDir = __DIR__ . DIRECTORY_SEPARATOR . 'scan_logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0700, true);
            @file_put_contents($logDir . DIRECTORY_SEPARATOR . '.htaccess', "Options -Indexes\nDeny from all");
        }
        $logFile = $logDir . DIRECTORY_SEPARATOR . 'scanlog_' . date('Ymd_His') . '.txt';
        $logContent = "--- Scanner by 6ickzone ---\n";
        $logContent .= "Date: " . date('c') . "\n";
        $logContent .= "Scan Path: " . $start . "\n";
        $logContent .= "Scan Recent Only (" . $modified_days . " days): " . ($modified_recent ? 'Yes' : 'No') . "\n";
        $logContent .= "Total Found: " . count($res) . "\n";
        $logContent .= "--- Log Results ---\n\n";
        
        if (empty($res)) {
            $logContent .= "No suspicious files found.\n";
        } else {
            foreach ($res as $fileEntry) {
                $logContent .= "[SUSPECT] " . $fileEntry['file'] . "\n";
                $logContent .= "  Size: " . $fileEntry['size'] . " bytes\n";
                $logContent .= "  Entropy: " . $fileEntry['entropy'] . "\n";
                $logContent .= "  Flags: " . implode(', ', $fileEntry['flags']) . "\n\n";
            }
        }
        @file_put_contents($logFile, $logContent);
        // --- End Log ---

        echo json_encode(['ok'=>true,'scanned'=>$start,'found'=>count($res),'results'=>$res]);
        exit;
    }

    if ($action === 'quarantine') {
        $file = $_POST['file'] ?? '';
        $dstDir = __DIR__ . DIRECTORY_SEPARATOR . 'quarantine';

        if (!is_dir($dstDir)) {
            mkdir($dstDir, 0700, true);
            $htaccessContent = "Options -Indexes\nDeny from all";
            @file_put_contents($dstDir . DIRECTORY_SEPARATOR . '.htaccess', $htaccessContent);
        }

        if ($file && is_file($file)) {
            $base = basename($file);
            $dst = $dstDir . DIRECTORY_SEPARATOR . time() . '_' . $base;
            $moved = @rename($file, $dst);
            echo json_encode(['ok'=>$moved,'dst'=>$moved?$dst:null]);
        } else echo json_encode(['ok'=>false,'error'=>'file_not_found']);
        exit;
    }
    
    if ($action === 'analyze') {
        $file = $_POST['file'] ?? '';
        if (!$file || !file_exists($file) || !is_readable($file)) {
            echo json_encode(['ok'=>false,'error'=>'Invalid file']);
            exit;
        }

        $content = file_get_contents($file);
        if ($content === false) {
            echo json_encode(['ok'=>false, 'error'=>'Cannot read file']);
            exit;
        }

        $lines = explode("\n", $content);
        $matches = [];
        $signatures = [
            '/\beval\s*\(/','/base64_decode\s*\(/','/gzinflate\s*\(/','/gzuncompress\s*\(/',
            '/shell_exec\s*\(/','/system\s*\(/','/exec\s*\(/','/passthru\s*\(/',
            '/popen\s*\(/','/proc_open\s*\(/','/assert\s*\(/','/create_function\s*\(/',
            '/`.+`/s','/preg_replace\s*\(.*e.* \(/is'
        ];

        foreach ($lines as $i => $line) {
            foreach ($signatures as $pattern) {
                if (@preg_match($pattern, $line)) {
                    $matches[] = ['line_num' => $i + 1, 'content' => trim($line), 'pattern' => trim($pattern, '/is')];
                }
            }
        }
        $entropy = round(shannon_entropy($content),3);

        echo json_encode([
            'ok'      => true,
            'file'    => $file,
            'size'    => filesize($file),
            'lines'   => count($lines),
            'entropy' => $entropy,
            'flags'   => [
                'high_entropy' => ($entropy > 4.5 && strlen($content) > 200),
                'matched_patterns' => array_unique(array_column($matches, 'pattern'))
            ],
            'matches' => $matches
        ]);
        exit;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown action']); exit;
}

// ---- Scanner core ----
function shannon_entropy($s){
    $len = strlen($s); if ($len === 0) return 0.0;
    $freq = array_count_values(str_split($s)); $entropy = 0.0;
    foreach ($freq as $c){ $p=$c/$len; $entropy -= $p*log($p,2); }
    return $entropy;
}

function run_scan($start='.', $maxDepth=10, $whitelistPatterns = [], $modified_recent = false, $modified_days = 7){
    $signatures = [
        '/\beval\s*\(/','/base64_decode\s*\(/','/gzinflate\s*\(/','/gzuncompress\s*\(/',
        '/shell_exec\s*\(/','/system\s*\(/','/exec\s*\(/','/passthru\s*\(/',
        '/popen\s*\(/','/proc_open\s*\(/','/assert\s*\(/','/create_function\s*\(/',
        '/`.+`/s','/preg_replace\s*\(.*e.* \(/is'
    ];
    $suspiciousNames = ['/\b(c99|r57|wso|webshell|uploader|backdoor|b374k)\b/i','/backup\d{0,4}\.php$/i'];
    $extensions = ['php','phtml','php5','inc','phar','shtml','asp','aspx','jsp'];
    $ignoreDirs = ['.git','.svn','node_modules','vendor','tmp','cache','.ht','scan_logs','quarantine'];
    
    $results = [];
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($start, FilesystemIterator::SKIP_DOTS));
    $rii->setMaxDepth(intval($maxDepth));
    
    $mtimeThreshold = strtotime("-{$modified_days} days");

    foreach ($rii as $file) {
        $rel = $file->getPathname();

        foreach ($whitelistPatterns as $pattern) {
            if ($pattern && @preg_match($pattern, $rel)) continue 2;
        }

        $skipFile = false;
        foreach ($ignoreDirs as $dir) {
            if (strpos($rel, $dir) !== false) {
                 $skipFile = true; break;
            }
        }
        if ($skipFile) continue;

        // Check MTime
        if ($modified_recent) {
            if ($file->getMTime() < $mtimeThreshold) continue;
        }

        if ($file->isDir()) continue;
        $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));

        $head = @file_get_contents($rel, false, null, 0, 1024);
        if ($head === false) continue;
        $isPhpLike = in_array($ext, $extensions) || preg_match('/<\?php/i',$head);
        if (!$isPhpLike) continue;

        $content = @file_get_contents($rel);
        if ($content === false) continue;

        $entry = [
            'file'     => $rel,
            'size'     => filesize($rel),
            'mtime'    => date('c',$file->getMTime()),
            'flags'    => [],
            'entropy'  => round(shannon_entropy($content),3),
            'perm'     => substr(sprintf('%o', fileperms($rel)), -4)
        ];

        foreach ($suspiciousNames as $pat) {
            if (preg_match($pat, basename($rel))) {
                $entry['flags'][] = 'filename_suspect';
                break;
            }
        }
        if ($entry['entropy'] > 4.5 && strlen($content)>200) $entry['flags'][]='high_entropy';
        foreach ($signatures as $sig) if (preg_match($sig, $content)) $entry['flags'][] = 'sig:'.trim($sig, '/is');
        if (preg_match('/iframe|<form[^>]+enctype=.*multipart/i', $content)) $entry['flags'][]='iframe_or_multipart_form';
        if (preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)\[[\'\"]/', $content)) $entry['flags'][]='dynamic_input_usage';
        if (strpos($entry['perm'],'777')!==false || strpos($entry['perm'],'666')!==false) $entry['flags'][]='weak_permission_'.$entry['perm'];

        if (!empty($entry['flags'])) $entry['md5'] = md5($content);
        if (!empty($entry['flags'])) $results[] = $entry;
    }
    return $results;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Webshell Scanner</title>
<style>
  body{ font-family:"Segoe UI",sans-serif; margin:18px; background:#f9fafb }
  .container { max-width:960px;margin:auto }
  .card{background:white;padding:14px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,0.05)}
  .row{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap; align-items: center;}
  input, textarea, select, button{padding:7px;border:1px solid #ccc;border-radius:5px; font-family:inherit; font-size:14px;}
  input[type="checkbox"] { width: auto; }
  button { cursor:pointer; background: #eee; }
  #scanBtn { background: #3b82f6; color: white; border-color: #3b82f6; }
  table{width:100%;border-collapse:collapse;font-size:13px;}
  th, td{padding:8px;border-bottom:1px solid #eee; text-align:left;}
  .badge{display:inline-block;padding:4px 6px;background:#ffeecc;font-size:11px;border-radius:4px; margin:2px;}
  .small{font-size:12px;color:#777}
  code { font-family: Consolas, 'Courier New', monospace; background: #f4f4f5; padding: 2px 4px; border-radius: 4px; }
  #analysisModal {
    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    width: 90%; max-width: 800px; background:white; padding:20px;
    border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,0.2); z-index:999; display:none;
  }
  #analysisModal h3 { margin-top: 0; }
  #analysisModal ul { max-height: 300px; overflow-y: auto; background: #f9fafb; border: 1px solid #eee; }
  #analysisModal li { margin-bottom: 5px; }
</style>
</head>
<body>

<div class="container">

<h2>Webshell Scanner v1.2.3</h2>

<div class="card">
  <div class="row">
    <input id="path" value="<?= htmlspecialchars(getcwd()) ?>" placeholder="Scan path..." style="flex:1"/>
    <input id="max_depth" value="10" style="width:90px;" />
    <button id="scanBtn">🔍 Scan Files</button>
  </div>

  <div class="row">
    <textarea id="whitelist_patterns"
              style="flex:1; height:80px; font-family: Consolas, monospace; font-size: 12px;"
              placeholder="Exclude regex patterns (one per line),&#10;e.g.: /vendor\/.*\.php$&#10;/safe_plugin_folder/"></textarea>
  </div>
  
  <div class="row">
    <input type="checkbox" id="modified_recent" style="width:auto;"/>
    <label for="modified_recent" style="font-size:14px;">Only scan files modified in the last</label>
    <input type="number" id="modified_days" value="7" style="width:60px;"/>
    <label for="modified_days" style="font-size:14px;">days</label>
    <div id="status" class="small" style="margin-left:auto;">Ready</div>
  </div>

  <div id="summary" class="small"></div>
  <div id="results"></div>
</div>

</div>

<div id="analysisModal">
  <h3>Analysis Detail — <span id="fileName">...</span></h3>
  <p class="small">
      Size: <strong id="fileSize">...</strong> &middot; 
      Lines: <strong id="lineCount">...</strong> &middot; 
      Entropy: <strong id="fileEntropy">...</strong>
  </p>
  <h4>Found Patterns:</h4>
  <ul id="flagList"></ul>
  <h4>Dangerous Line Matches:</h4>
  <ul id="matchList"></ul>
  <button onclick="document.getElementById('analysisModal').style.display='none'">Close</button>
</div>


<script>
async function post(data){
  const f = new FormData();
  for(const k in data) f.append(k,data[k]);
  const res = await fetch('',{method:'POST',body:f});
  return res.json();
}

document.getElementById('scanBtn').addEventListener('click', async () => {
  const path = document.getElementById('path').value;
  const max_depth = parseInt(document.getElementById('max_depth').value) || 10;
  const patternsRaw = document.getElementById('whitelist_patterns').value;
  
  const modified_recent = document.getElementById('modified_recent').checked;
  const modified_days = document.getElementById('modified_days').value;

  document.getElementById('status').innerText = 'Scanning...';
  const btn = document.getElementById('scanBtn'); btn.disabled = true;

  try {
    const j = await post({
        action:'scan', 
        path, 
        max_depth, 
        whitelist_patterns: patternsRaw,
        modified_recent: modified_recent,
        modified_days: modified_days
    });
    
    document.getElementById('status').innerText = `✔ Found ${j.found} file${j.found != 1 ? 's' : ''}`;
    displayResults(j.results);
  } catch (err) {
    console.error(err);
    document.getElementById('status').innerText = '⚠ Error occurred.';
  } finally {
    btn.disabled = false;
  }
});

function displayResults(items){
  const el = document.getElementById('results');
  if (!items || items.length == 0) {
    el.innerHTML = '<div>No suspicious files found 🐣</div>';
    return;
  }

  let rows = `<table cellpadding="4"><thead><tr>
    <th width="35%">File</th>
    <th width="25%">Flags</th>
    <th>Entropy</th>
    <th>MD5</th>
    <th># Actions</th>
  </tr></thead><tbody>`;
  
  for(const item of items){
    let f = "";
    if(item.flags) f=item.flags.map(x=>`<div class="badge">${escapeHTML(x)}</div>`).join(' ');

    rows += 
      `<tr>
        <td><code>${escapeHTML(item.file)}</code><br/><small>${item.mtime}</small></td>
        <td>${f}</td>
        <td>${item.entropy || ''}</td>
        <td><code>${item.md5?.substring(0,6) || '-'}</code></td>
        <td>
          <button onclick="analyzeFile('${encodeURIComponent(item.file)}', this)">🔍 Analyze</button>
          <button onclick="toQuarantine('${encodeURIComponent(item.file)}', this)">🚫 Quarantine</button>
        </td>
      </tr>`;
  }
  rows += '</tbody></table>';
  el.innerHTML = rows;
}
  

function escapeHTML(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

async function toQuarantine(fileEncoded, btn){
  if(!confirm(`Move selected file to quarantine?\n(${decodeURIComponent(fileEncoded)})`)) return;
  btn.disabled = true;
  const resp = await post({action:'quarantine',file:decodeURIComponent(fileEncoded)});
  if(resp.ok) {
    alert('✅ File moved successfully!');
    btn.closest('tr').remove();
  } else {
    alert('❌ Failed to move.');
    btn.disabled = false;
  }
}

async function analyzeFile(fileEncoded, btn) {
    const modal = document.getElementById('analysisModal');
    if (btn) btn.disabled = true;
    
    modal.style.display = 'block';
    document.getElementById('fileName').innerText = 'Loading...';
    document.getElementById('fileSize').innerText = '...';
    document.getElementById('lineCount').innerText = '...';
    document.getElementById('fileEntropy').innerText = '...';
    document.getElementById('flagList').innerHTML = '<li>Loading...</li>';
    document.getElementById('matchList').innerHTML = '<li>Loading...</li>';

    try {
        const j = await post({action: 'analyze', file: decodeURIComponent(fileEncoded)});
        
        if (!j.ok) {
            alert('Error: ' + j.error);
            modal.style.display = 'none';
            return;
        }

        document.getElementById('fileName').innerText = j.file;
        document.getElementById('fileSize').innerText = j.size + ' bytes';
        document.getElementById('lineCount').innerText = j.lines;
        document.getElementById('fileEntropy').innerText = j.entropy + (j.flags.high_entropy ? ' (HIGH)' : '');

        const flagList = document.getElementById('flagList');
        flagList.innerHTML = '';
        if (j.flags.matched_patterns.length > 0) {
            j.flags.matched_patterns.forEach(flag => {
                const li = document.createElement('li');
                li.innerHTML = `<code>${escapeHTML(flag)}</code>`;
                flagList.appendChild(li);
            });
        } else {
             flagList.innerHTML = '<li>-</li>';
        }

        const matchList = document.getElementById('matchList');
        matchList.innerHTML = '';
        if (j.matches.length === 0) {
            matchList.innerHTML = '<li>No specific line matches found.</li>';
        } else {
            j.matches.forEach(match => {
                const li = document.createElement('li');
                li.innerHTML = `<strong>L:${match.line_num}</strong> (<code>${escapeHTML(match.pattern)}</code>): <code>${escapeHTML(match.content)}</code>`;
                matchList.appendChild(li);
            });
        }
        
    } catch (e) {
        console.error(e);
        alert('Failed to analyze file.');
        modal.style.display = 'none';
    } finally {
        if (btn) btn.disabled = false;
    }
}
</script>

</body>
</html>