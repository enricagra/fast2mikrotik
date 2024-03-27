<?php
require('routeros_api.class.php');

/* Set your specific configuration below */
$fastlog = "/var/log/suricata/fast.log";
$mikrotik_addr = "__someip__";
$mikrotik_user = "admin";
$mikrotik_pwd = "__somesecret__";
$local_ip_prefix = "192.168.";
$block_time = "01:00:00";
/* Set email_alert to true if you'd like to get email messages when a block is sent to the Mikrotik */
$email_alert = false;
$email_to = "__someemail__yourself@xyz.com";
$email_from = "__someemail__root@xyz.com";

header('Content-Type: text/plain');

$API = new RouterosAPI();

/**
* Tail a file (UNIX only!)
* Watch a file for changes using inotify and return the changed data
*
* @param string $file - filename of the file to be watched
* @param integer $pos - actual position in the file
* @return string
*/
function tail($file,&$pos) {
    $buf='';
    // get the size of the file
    if(!$pos) $pos = filesize($file);
    // Open an inotify instance
    $fd = inotify_init();
    // Watch $file for changes.
    $watch_descriptor = inotify_add_watch($fd, $file, IN_ALL_EVENTS);
    // Loop forever (breaks are below)
    while (true) {
        // Read events (inotify_read is blocking!)
        $events = inotify_read($fd);
        // Loop though the events which occured
        foreach ($events as $event=>$evdetails) {
            // React on the event type
            switch (true) {
                // File was modified
                case ($evdetails['mask'] & IN_MODIFY):
                    // Stop watching $file for changes
                    inotify_rm_watch($fd, $watch_descriptor);
                    // Close the inotify instance
                    fclose($fd);
                    // open the file
                    $fp = fopen($file,'r');
                    if (!$fp) return false;
                    // seek to the last EOF position
                    fseek($fp,$pos);
                    // read until EOF
                    while (!feof($fp)) {
                        $buf .= fread($fp,8192);
                    }
                    // save the new EOF to $pos
                    $pos = ftell($fp); // (remember: $pos is called by reference)
                    // close the file pointer
                    fclose($fp);
                    // return the new data and leave the function
                    return $buf;
                    // be a nice guy and program good code ;-)
                    break;

                    // File was moved or deleted
                case ($evdetails['mask'] & IN_MOVE):
                case ($evdetails['mask'] & IN_MOVE_SELF):
                case ($evdetails['mask'] & IN_DELETE):
                case ($evdetails['mask'] & IN_DELETE_SELF):
                    // Stop watching $file for changes
                    inotify_rm_watch($fd, $watch_descriptor);
                    // Close the inotify instance
                    fclose($fd);
                    // Return a failure
                    return false;
                    break;
            }
        }
    }
}

function AddToFirewall($thisalert, $srcdst) {

  global $local_ip_prefix, $API, $mikrotik_addr, $mikrotik_user, $mikrotik_pwd, $block_time, $email_to, $email_from, $email_alert;

  /* Determine the target external address */
  if ((strpos($srcdst[0], $local_ip_prefix) === false) and
      (strpos($srcdst[0], "127.0.0.1") === false)) {
     $target = $srcdst[0];
  } else {
     $target = $srcdst[1];
  }   
  try {
      $API->connect($mikrotik_addr, $mikrotik_user, $mikrotik_pwd);
  } catch (Exception $e) {
      die('Unable to connect to RouterOS. Error:' . $e);
  }
  $ARRAY = $API->comm("/ip/firewall/address-list/print", array(
     ".proplist"=> ".id",
     "?address" => $target,));
  foreach ($ARRAY as $a) {
    foreach ($a as $name => $value) {
      $API->write("/ip/firewall/address-list/remove",false);
      $API->write("=.id=$value",true);
      $API->read();
    }
  }
  $API->comm("/ip/firewall/address-list/add", array(
    "list" => "Blocked",
    "address" => $target,
    "timeout" => $block_time,
    "comment" => "From suricata, " . $thisalert[1] .
       " => event timestamp: " . $thisalert[0],));
  $API->disconnect();
  if ($email_alert) {
    $to      = $email_to;
    $subject = 'Suricata on ' . gethostname() . ': blocked IP address ' . $target;
    $message = 'The IP address ' . $target . " has been blocked due to the following rule match:\r\n";
    $message = $message . "\r\n";
    $message = $message . "The signature ID is " . $thisalert[1] . "\r\n";
    $message = $message . "    event timestamp: " . $thisalert[0] . " blocked for: " . $block_time . "\r\n\r\n";
    $headers = 'From: ' . $email_from . "\r\n" .
      'Reply-To: ' . $email_from . "\r\n" .
      'X-Mailer: PHP/' . phpversion();
    mail($to, $subject, $message, $headers);
  }
  return true;
}

$lastpos = 0;
while (true) {
  $alertstr = tail($fastlog,$lastpos);
  foreach (preg_split("/((\r?\n)|(\r\n?))/", $alertstr) as $line){
    if (strlen($line) > 0) {
      $thisalert = explode("[**]", $line);
      $thisalert[0] = trim($thisalert[0]);
      $thisalert[1] = trim($thisalert[1]);
      $thisalert[2] = trim($thisalert[2]);
      $tmpstr = explode("}", $thisalert[2]);
      $srcdst = explode("->", $tmpstr[1]);
      $tmpstr = explode(":", $srcdst[0]);
      $srcdst[0] = trim($tmpstr[0]);
      $tmpstr = explode(":", $srcdst[1]);
      $srcdst[1] = trim($tmpstr[0]);
      AddToFirewall($thisalert, $srcdst);
    }
  }   
}
?>
