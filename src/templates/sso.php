<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
    <title>PHP SAML SDK Sample - SSO</title>
</head>
<body onload="document.getElementById('saml_form').submit();">
<form id="saml_form" action="<?php echo $samlConfig->getSsoPostUrl(); ?>" method="post">
    <input type="hidden" name="SAMLRequest" value="<?php echo $xmlBase64;?>" />
    <noscript>
        <input type="submit" value="Login" />
    </noscript>
</form>
</body>
</html>