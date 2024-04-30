<?php
@error_reporting(E_ALL);
$file = $_FILES['file'];
if (!isset($file)){
    die('upload error');
}
$result = move_uploaded_file($file['tmp_name'], $file['name']);

if ($result){
    echo 'upload success';
}else{
    echo 'upload error';
}