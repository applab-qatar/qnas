<?php
namespace Applab\QNas;

use Applab\NasSdk\AttributeQueryClient;
use Applab\NasSdk\SamlConfig;
use Applab\NasSdk\SingleSignOnClient;
use Applab\NasSdk\SingleLogoutClient;
use Applab\NasSdk\Utils\SamlSdkUtils;

class QatarNAS
{
    private function init()
    {
        $baseDir = dirname(dirname(dirname(dirname(__DIR__))));
        require_once($baseDir."/qnas_config/config.php");
    }
    public static function sso()
    {
        self::init();
        // Create SAML config and SingleSignOnClient instances
        $samlConfig = new SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $singleSignOnClient = new SingleSignOnClient($samlConfig);

        $samlRequest = $singleSignOnClient->generateRequest($_GET['lang'], array('urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI'));

        // Get the Base64 value of the SAML AuthnRequest message for the submission
        $xmlBase64 = base64_encode($samlRequest->getRequest());

        // Store the SAML request ID for response validation
        $_SESSION["user"]["resp_id"] = $samlRequest->getId();
        //echo $samlConfig->getSsoPostUrl();exit;
        //var_dump($_SESSION);exit;
        return include('templates/sso.php');
    }

    public static function sls()
    {
        self::init();
        $samlConfig = new SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $singleLogoutClient = new SingleLogoutClient($samlConfig);

        /**
         *  Processing of Single Logout requests/responses
         */
        if (isset($_GET["SAMLRequest"])) {
            $request = SamlSdkUtils::computeXml($_SERVER['QUERY_STRING'], $samlConfig->getIdpCert());
            if (!SamlSdkUtils::startsWith($request, "Error")) {
                // Process the SAML LogoutRequest message
                $response = $singleLogoutClient->generateResponse($request);

                // Create the SAML LogoutResponse message
                $location = SamlSdkUtils::computeUrl("Response",  $samlConfig->getSpPrivateKeyFile(), $samlConfig->getSlsRedirectUrl(), $response);

                // Perform local logout
                unset($_SESSION["user"]);

                // Perform HTTP-Redirect binging with the LogoutResponse message
                SamlSdkUtils::redirect("$location");
            }
        } else if (isset($_GET["SAMLResponse"])) {
            $response = SamlSdkUtils::computeXml($_SERVER['QUERY_STRING'], $samlConfig->getIdpCert());
            if (!SamlSdkUtils::startsWith($response, "Error")) {
                try {
                    $samlCredential = $singleLogoutClient->processResponse($response, $_SESSION["user"]["resp_id"]);
                    if ($samlCredential->isSuccess()) {
                        // Clean up user session
                        unset($_SESSION["user"]["resp_id"]);
                        unset($_SESSION["user"]);
                        SamlSdkUtils::redirect("../");
                    } else {
                        SamlSdkUtils::redirectWithError("../", "Logout failed on the server. Use local logout.");
                    }
                } catch (Exception $e) {
                    SamlSdkUtils::redirectWithError("../", $e->getMessage());
                }
            } else {
                SamlSdkUtils::redirectWithError("../", $response);
            }
        } else if (isset($_SESSION["user"]) && $_SESSION["user"]["loggedin"]) {
            // Authenticated user identification
            $nameId = $_SESSION["user"]["subject"];

            // Current session identification
            $sessionIndex = $_SESSION["user"]["attributes"]["qatar_session_identification"]["value"];

            // Generate SAML LogoutRequest message
            $samlRequest = $singleLogoutClient->generateRequest($nameId, $sessionIndex, $_GET['lang']);

            // Create HTTP-Redirect binding with LogoutRequest message
            $location = SamlSdkUtils::computeUrl("Request", $samlConfig->getSpPrivateKeyFile(), $samlConfig->getSlsRedirectUrl(), $samlRequest->getRequest());

            // Keep the LogoutRequest message ID for later verification
            $_SESSION["user"]["resp_id"] = $samlRequest->getId();

            // Perform the HTTP-Post binding with the LogoutRequest message
            SamlSdkUtils::redirect($location);
        } else {
            SamlSdkUtils::redirect("../");
        }
    }

    public static function attr()
    {
        self::init();
        $samlConfig = new SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $attributeQueryClient = new AttributeQueryClient($samlConfig);
        if (isset($_GET["clear"])) {
            unset($_SESSION["user"]["attrs_query"]);
            SamlSdkUtils::redirect("../");
        } else {
            // Create the SAML AttributeQuery message
            $samlRequest = $attributeQueryClient->generateRequest($_SESSION["user"]["subject"], array());

            // Store the message ID
            $_SESSION["user"]["resp_id"] = $samlRequest->getId();

            // Sends the AttributeQuery request via SOAP and get response
            $response = SamlSdkUtils::soapCall($samlRequest->getRequest(), $samlConfig->getAqUrl());

            if (SamlSdkUtils::startsWith($response, "HTTP") && strpos($response, "<html") === false) {
                try {
                    // Extract the SAML (Authn) Response message
                    $response = SamlSdkUtils::processSoapMsg($response);

                    // Process the SAML (Authn) Response message
                    $samlCredential = $attributeQueryClient->processResponse($response, $_SESSION["user"]["resp_id"]);

                    if ($samlCredential->isSuccess()) {
                        $_SESSION["user"]["subject"] = $samlCredential->getNameId();
                        $_SESSION["user"]["idp_entity_id"] = $samlCredential->getIdpEntityId();
                        $_SESSION["user"]["attrs_query"] = $samlCredential->getAttributes();
                        SamlSdkUtils::redirect("../");
                    } else {
                        SamlSdkUtils::redirectWithError("../", "Error attribute query: No succes status find!");
                    }
                } catch (Exception $e) {
                    SamlSdkUtils::redirectWithError("../", "Error attribute query: Cannot parse SAML response!<br/>The SAML Response is:<br/>".htmlspecialchars($response, ENT_XML1, 'UTF-8')."<br/><br/> The exception is:<br/>".htmlspecialchars($e, ENT_XML1, 'UTF-8'));
                }
            } else {
                if (strpos($response, "<html") !== false) {
                    $pos = strpos($response, "\r\n\r\n");
                    if ($pos !== false) {
                        $response = substr($response, $pos, strlen($response) - $pos);
                    }
                    SamlSdkUtils::redirectWithError("../", $response);
                } else {
                    SamlSdkUtils::redirectWithError("../", "Error while getting attributes: ".$response);
                }
            }
        }
    }

    public static function acs()
    {
        self::init();
        if (isset($_REQUEST["SAMLResponse"])) {
            // Decode SAMLResponse Base64 value
            $resp = base64_decode($_REQUEST["SAMLResponse"]);
            try {
                // Create SAML config and SingleSignOnClient instances
                $samlConfig = new SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
                $singleSignOnClient = new SingleSignOnClient($samlConfig);

                // Process the SAML Response value; verify against the AuthnRequest ID value
                $samlCredential = $singleSignOnClient->processResponse($resp, $_SESSION["user"]["resp_id"]);

                unset($_SESSION["user"]["resp_id"]);

                // Check if the authentication was successful or not
                if ($samlCredential->isSuccess()) {
                    $_SESSION["user"]["loggedin"] = true;
                    $_SESSION["user"]["subject"] = $samlCredential->getNameId();
                    $_SESSION["user"]["authn_method"] = $samlCredential->getAuthMethod();
                    $_SESSION["user"]["idp_entity_id"] = $samlCredential->getIdpEntityId();
                    $_SESSION["user"]["attributes"] = $samlCredential->getAttributes();
                    if ($samlCredential->getAuthMethod() == "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI") {
                        $_SESSION["user"]["csnToken"] = $samlCredential->getAttributeValue("UserCardSerialNumberToken");
                        $_SESSION["user"]["sloUrl"] = $samlConfig->getSlsRedirectUrl()."-idp?sp=".$samlConfig->getSpEntityId();
                        $_SESSION["user"]["idpUrl"] = $samlConfig->getIdpBaseUrl();
                    }
                    SamlSdkUtils::redirect('../');
                } else {
                    SamlSdkUtils::redirectWithError('../', "Not successful login (".$samlCredential->getStatus()."; ".$samlCredential->getStatusMessage().")");
                }
            } catch (Exception $e) {
                SamlSdkUtils::redirectWithError('../', $e->getMessage());
            }
        } else {
            SamlSdkUtils::redirect('../', "HTTP GET method is not supported");
        }
    }
}