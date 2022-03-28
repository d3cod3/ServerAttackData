<?php

function random_valid_public_ip() {
    $ip = mt_rand(0, 255) . '.' .mt_rand(0, 255) . '.' .mt_rand(0, 255) . '.' .mt_rand(0, 255);

    // Return the IP if it is a valid IP, generate another IP if not
    if (!ip_in_range($ip, '10.0.0.0', '10.255.255.255') && !ip_in_range($ip, '172.16.0.0', '172.31.255.255') && !ip_in_range($ip, '192.168.0.0', '192.168.255.255') ) {
      return $ip;
    } else {
      return random_valid_public_ip();
    }
  }

function ip_in_range($ip, $start, $end) {
  $i = explode('.', $ip);
  $s = explode('.', $start);
  $e = explode('.', $end);
  return in_array($i[0], range($s[0], $e[0])) && in_array($i[1], range($s[1], $e[1])) && in_array($i[2], range($s[2], $e[2])) && in_array($i[3], range($s[3], $e[3]));
}

$myIP = random_valid_public_ip();

echo $myIP;

?>
