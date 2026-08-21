#!/bin/sh

: "${RSCTF_FLAG:?RSCTF_FLAG is required}"
FLAG=$RSCTF_FLAG
unset RSCTF_FLAG


WEB_ROOT="/app/public"
mkdir -p "$WEB_ROOT"
cd "$WEB_ROOT" || exit

# git init
git init
git config user.email "admon@mail.com"
git config user.name "Administrator"

# create php files
cat <<EOF > header.php
<?php
// Validasi session
if (!isset(\$_SESSION['login'])) {
    header("Location: login.php");
    exit;
}

\$FLAG = "${FLAG}";
?>
EOF

cat <<EOF > index.php
<?php
session_start();
include 'header.php';

echo "Welcome to the admin panel. Your flag is " . \$FLAG;
?>
EOF

# Commit the files
git add .
git commit -m "Initial commit of admin panel"

# Create Maintenance Page
rm index.php header.php

cat <<EOF > index.html
<!DOCTYPE html>
<html>
<head>
    <title>Maintenance</title>
    <style>
        body {
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: sans-serif;
        }
        h1 {
            font-size: 3em;
            color: #333;
        }
    </style>
</head>
<body>
    <h1>Maintenance</h1>
</body>
</html>
EOF

# Commit Maintenance Page
git add .
git commit -m "Switch to maintenance mode"

# Start Go Server
cd /app

rm -- "$0"

exec ./server
