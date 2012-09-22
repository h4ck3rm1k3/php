--TEST--
Bug #45877 (Array key '2147483647' left as string)
--FILE--
<?php
$max = sprintf("%d", PHP_INT_MAX);
switch($max) {
case "2147483647": /* 32-bit systems */
	$min = "-2147483648";
	$overflow = "2147483648";
	$underflow = "-2147483649";
	break;
case "9223372036854775807": /* 64-bit systems */
	$min = "-9223372036854775808";
	$overflow = "9223372036854775808";
	$underflow = "-9223372036854775809";
	break;
default:
	die("failed: unknown value for PHP_MAX_INT");
	break;
}

function test_value($val, $msg) {
	$a = array($val => 1);
	$keys = array_keys($a);
	if ($val == $keys[0]) $result = "ok";
	else $result = "failed ($val != $keys[0])";
	echo "$msg: $result\n";
}

test_value($max, "max");
test_value($overflow, "overflow");
test_value($min, "min");
test_value($underflow, "underflow");

?>
--EXPECT--
max: ok
overflow: ok
min: ok
underflow: ok
