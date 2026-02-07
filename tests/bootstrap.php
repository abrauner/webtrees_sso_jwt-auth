<?php

declare(strict_types=1);

// Load the module's own autoloader (includes all dependencies)
$loader = require dirname(__DIR__) . '/vendor/autoload.php';

// webtrees' TestCase is under autoload-dev, so it's not autoloaded when
// webtrees is installed as a dependency — require it explicitly.
require_once dirname(__DIR__) . '/vendor/fisharebest/webtrees/tests/TestCase.php';
