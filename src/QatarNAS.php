<?php
namespace Applab\QNas;

use Symfony\Component\HttpFoundation\Request;

class QatarNAS
{
    private static function init()
    {
        $baseDir = dirname(dirname(dirname(dirname(__DIR__))));
        require_once($baseDir."/qnas_config/config.php");
        define("SP_SDK_ROOT", dirname(__FILE__) . "/sdk/");
        require_once(SP_SDK_ROOT."/SamlConfig.php");
    }
    /**
     * PHP Sample SP - SAML authentication request
     */
    public static function singleSignOnClient($lang,$authMethod = [],Request $request )
    {
        self::init();
        require_once(SP_SDK_ROOT."/SingleSignOnClient.php");
        // Create SAML config and SingleSignOnClient instances
        $samlConfig = new \SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $singleSignOnClient = new \SingleSignOnClient($samlConfig);

        $samlRequest = $singleSignOnClient->generateRequest($lang, $authMethod);

        // Get the Base64 value of the SAML AuthnRequest message for the submission
        $xmlBase64 = base64_encode($samlRequest->getRequest());

        // Store the SAML request ID for response validation
        $session = $request->getSession();
        $session->set('user_resp_id', $samlRequest->getId());
//        $_SESSION["user"]["resp_id"] = $samlRequest->getId();
        return include('templates/sso.php');
    }
    /**
     * PHP Sample SP - Assertion Consumer Service
     */
    public static function singleSignOnResponse(Request $request)
    {
        self::init();
        require_once(SP_SDK_ROOT."/SingleSignOnClient.php");
        /**
         *  Processing responses
         */
        if (isset($_REQUEST["SAMLResponse"])) {
            // Decode SAMLResponse Base64 value
            $resp = base64_decode($_REQUEST["SAMLResponse"]);
            try {
                // Create SAML config and SingleSignOnClient instances
                $samlConfig = new \SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
                $singleSignOnClient = new \SingleSignOnClient($samlConfig);
                $session=$request->getSession();
                // Process the SAML Response value; verify against the AuthnRequest ID value
                $samlCredential = $singleSignOnClient->processResponse($resp, $session->get('user_resp_id'));
                $session->remove('user_resp_id');
               // unset($_SESSION["user"]["resp_id"]);
                // Check if the authentication was successful or not
                if ($samlCredential->isSuccess()) {
//                    $_SESSION["user"]["loggedin"] = true;
//                    $_SESSION["user"]["subject"] = $samlCredential->getNameId();
//                    $_SESSION["user"]["authn_method"] = $samlCredential->getAuthMethod();
//                    $_SESSION["user"]["idp_entity_id"] = $samlCredential->getIdpEntityId();
//                    $_SESSION["user"]["attributes"] = $samlCredential->getAttributes();
//                    if ($samlCredential->getAuthMethod() == "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI") {
//                        $_SESSION["user"]["csnToken"] = $samlCredential->getAttributeValue("UserCardSerialNumberToken");
//                        $_SESSION["user"]["sloUrl"] = $samlConfig->getSlsRedirectUrl()."-idp?sp=".$samlConfig->getSpEntityId();
//                        $_SESSION["user"]["idpUrl"] = $samlConfig->getIdpBaseUrl();
//                    }
                    return ['status'=>true,'result'=>$samlCredential];
                } else {
                    return json_encode(['status'=>false,'error'=>['message'=>$samlCredential->getStatusMessage()]]);
                    //SamlSdkUtils::redirectWithError('../', "Not successful login (".$samlCredential->getStatus()."; ".$samlCredential->getStatusMessage().")");
                }
            } catch (Exception $e) {
                return json_encode(['status'=>false,'error'=>['message'=>$e->getMessage()]]);
                //\SamlSdkUtils::redirectWithError('../', $e->getMessage());
            }
        } else {
            return json_encode(['status'=>false,'error'=>['message'=>"Empty SAMLResponse"]]);
            //\SamlSdkUtils::redirect('../', "HTTP GET method is not supported");
        }
    }

    /**
     * PHP Sample SP - SAML logout service
     */
    public static function singleLogoutClient()
    {
        self::init();
        require_once(SP_SDK_ROOT."/SingleLogoutClient.php");
        $samlConfig = new \SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $singleLogoutClient = new \SingleLogoutClient($samlConfig);

        /**
         *  Processing of Single Logout requests/responses
         */
        if (isset($_GET["SAMLRequest"])) {
            $request = \SamlSdkUtils::computeXml($_SERVER['QUERY_STRING'], $samlConfig->getIdpCert());
            if (!\SamlSdkUtils::startsWith($request, "Error")) {
                // Process the SAML LogoutRequest message
                $response = $singleLogoutClient->generateResponse($request);

                // Create the SAML LogoutResponse message
                $location = \SamlSdkUtils::computeUrl("Response",  $samlConfig->getSpPrivateKeyFile(), $samlConfig->getSlsRedirectUrl(), $response);

                // Perform local logout
                unset($_SESSION["user"]);

                // Perform HTTP-Redirect binging with the LogoutResponse message
                \SamlSdkUtils::redirect("$location");
            }
        } else if (isset($_GET["SAMLResponse"])) {
            $response = \SamlSdkUtils::computeXml($_SERVER['QUERY_STRING'], $samlConfig->getIdpCert());
            if (!\SamlSdkUtils::startsWith($response, "Error")) {
                try {
                    $samlCredential = $singleLogoutClient->processResponse($response, $_SESSION["user"]["resp_id"]);
                    if ($samlCredential->isSuccess()) {
                        // Clean up user session
                        unset($_SESSION["user"]["resp_id"]);
                        unset($_SESSION["user"]);
                        \SamlSdkUtils::redirect("../");
                    } else {
                        \SamlSdkUtils::redirectWithError("../", "Logout failed on the server. Use local logout.");
                    }
                } catch (Exception $e) {
                    \SamlSdkUtils::redirectWithError("../", $e->getMessage());
                }
            } else {
                \SamlSdkUtils::redirectWithError("../", $response);
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
            \SamlSdkUtils::redirect($location);
        } else {
            \SamlSdkUtils::redirect("../");
        }
    }
    /**
     * PHP Sample SP - Attribute Query Service
     */
    public static function attributeQueryClient()
    {
        self::init();
        require_once(SP_SDK_ROOT."/AttributeQueryClient.php");
        $samlConfig = new \SamlConfig(CONFIG_ROOT.SP_METADATA_FILE, CONFIG_ROOT.IDP_METADATA_FILE, CONFIG_ROOT.SP_PRIV_KEY_FILE, CONFIG_ROOT.SP_CERT_FILE);
        $attributeQueryClient = new \AttributeQueryClient($samlConfig);
        /**
         *  Getting/Clearing attributes
         */
        if (isset($_GET["clear"])) {
            unset($_SESSION["user"]["attrs_query"]);
            \SamlSdkUtils::redirect("../");
        } else {
            // Create the SAML AttributeQuery message
            $samlRequest = $attributeQueryClient->generateRequest($_SESSION["user"]["subject"], array());

            // Store the message ID
            $_SESSION["user"]["resp_id"] = $samlRequest->getId();

            // Sends the AttributeQuery request via SOAP and get response
            $response = \SamlSdkUtils::soapCall($samlRequest->getRequest(), $samlConfig->getAqUrl());

            if (\SamlSdkUtils::startsWith($response, "HTTP") && strpos($response, "<html") === false) {
                try {
                    // Extract the SAML (Authn) Response message
                    $response = \SamlSdkUtils::processSoapMsg($response);

                    // Process the SAML (Authn) Response message
                    $samlCredential = $attributeQueryClient->processResponse($response, $_SESSION["user"]["resp_id"]);

                    if ($samlCredential->isSuccess()) {
                        $_SESSION["user"]["subject"] = $samlCredential->getNameId();
                        $_SESSION["user"]["idp_entity_id"] = $samlCredential->getIdpEntityId();
                        $_SESSION["user"]["attrs_query"] = $samlCredential->getAttributes();
                        \SamlSdkUtils::redirect("../");
                    } else {
                        \SamlSdkUtils::redirectWithError("../", "Error attribute query: No succes status find!");
                    }
                } catch (Exception $e) {
                    \SamlSdkUtils::redirectWithError("../", "Error attribute query: Cannot parse SAML response!<br/>The SAML Response is:<br/>".htmlspecialchars($response, ENT_XML1, 'UTF-8')."<br/><br/> The exception is:<br/>".htmlspecialchars($e, ENT_XML1, 'UTF-8'));
                }
            } else {
                if (strpos($response, "<html") !== false) {
                    $pos = strpos($response, "\r\n\r\n");
                    if ($pos !== false) {
                        $response = substr($response, $pos, strlen($response) - $pos);
                    }
                    \SamlSdkUtils::redirectWithError("../", $response);
                } else {
                    \SamlSdkUtils::redirectWithError("../", "Error while getting attributes: ".$response);
                }
            }
        }
    }
}