<?php
/******************************************************************************
 * (c) Copyright Gemalto, 2018                                                *
 * ALL RIGHTS RESERVED UNDER COPYRIGHT LAWS.                                  *
 * CONTAINS CONFIDENTIAL AND TRADE SECRET INFORMATION.                        *
 *                                                                            *
 * GEMALTO MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF    *
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED         *
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A                *
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. GEMALTO SHALL NOT BE              *
 * LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,          *
 * MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.                *
 * THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE     *
 * CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE            *
 * PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT      *
 * NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE      *
 * SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE          *
 * SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE          *
 * PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). GEMALTO         *
 * SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR      *
 * HIGH RISK ACTIVITIES.                                                      *
 ******************************************************************************/

/**
 * Constants for PHP SP SDK
 */

define('SHIB_PROTOCOL_NS', "urn:oasis:names:tc:SAML:2.0:protocol");
define('SHIB_ASSERT_NS', "urn:oasis:names:tc:SAML:2.0:assertion");
define('DSS_NS', "urn:oasis:names:tc:dss:1.0:core:schema");

define('RSA_SHA1', "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
define('RSA_SHA256', "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

/**
 * SAML SDK Utils
 */
class SamlSdkUtils
{
	/**
	 * HTTP Redirection using the Location HTTP header
	 *
	 * @param $url
	 * @param bool $permanent
	 */
	public static function redirect($url, $permanent = false)
	{
		header('Location: ' . $url, true, $permanent ? 301 : 302);
		exit();
	}

	/**
	 * HTTP Redirection with storing errorMessage into session
	 *
	 * @param $url
	 * @param $errorMessage
	 * @param bool $permanent
	 */
	public static function redirectWithError($url, $errorMessage, $permanent = false)
	{
		$_SESSION['errorMessage'] = $errorMessage;
		SamlSdkUtils::redirect($url, $permanent);
	}

	public static function computeUrl($type, $privKey, $slsUrl, $samlXml, $relayState = "")
	{
		require_once(SP_SDK_ROOT . '/xmlseclibs/xmlseclibs.php');

		$url = 'SAML' . $type . '=' . urlencode(base64_encode(gzdeflate($samlXml)));
		if ($relayState != "") {
			$url .= '&RelayState=' . urlencode($relayState);
		}
		$url .= '&SigAlg=' . urlencode(RSA_SHA256);

		$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
		$objKey->loadKey($privKey, TRUE);
		$signature = $objKey->signData($url);

		$url .= '&Signature=' . urlencode(base64_encode($signature));
		$url = $slsUrl . "?" . $url;

		return $url;
	}

	public static function computeXml($query, $cert)
	{
		require_once(SP_SDK_ROOT . '/xmlseclibs/xmlseclibs.php');

		$data = SamlSdkUtils::parseQuery($query);
		if ($data['SigAlg'] == RSA_SHA1) {
			$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
		} else if ($data['SigAlg'] == RSA_SHA256) {
			$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
		} else {
			return "Error parsing SAML response: Unknown signature algorithm: " . $data['SigAlg'];
		}

		$signature = base64_decode($data['Signature']);

		$objKey->loadKey($cert);

		if (!$objKey->verifySignature($data['SignedQuery'], $signature))
			return "Error parsing SAML response: Unable to validate signature on SAML message response!";

		if (array_key_exists('SAMLRequest', $data)) {
			$msg = $data['SAMLRequest'];
		} elseif (array_key_exists('SAMLResponse', $data)) {
			$msg = $data['SAMLResponse'];
		}

		return gzinflate(base64_decode($msg));
	}

	public static function soapCall($requestXml, $location, $timeout = 10)
	{
		$request = SamlSdkUtils::getSoapMsg($requestXml);
		$urlParts = parse_url($location);
		$host = $urlParts['host'];
		$port = (isset($urlParts['port']) ? $urlParts['port'] : "80");

		$httpReq = 'POST ' . $location . ' HTTP/1.1' . "\r\n";
		$httpReq .= 'Host: ' . $host . "\r\n";
		$httpReq .= "Content-Type: text/xml;charset=UTF-8\r\n";
		if (isset($_SESSION["user"]["attributes"]["qatar_session_identification"])) {
			$httpReq .= "Set-Cookie: " . SamlSdkUtils::jsonToHeader($_SESSION["user"]["attributes"]["qatar_session_identification"]["value"]) . " Secure\r\n";
		}
		$httpReq .= "Cache-control: no-cache, no-store\r\n";
		$httpReq .= "Pragma: no-cache\r\n";
		$httpReq .= "SoapAction: http://www.oasis-open.org/committees/security\r\n";
		$httpReq .= "Content-Length: " . strlen($request) . "\r\n";
		$httpReq .= "Connection: close\r\n";
		$httpReq .= "\r\n";
		$httpReq .= $request;
		if ($urlParts['scheme'] == 'https') {
			if (!isset($urlParts['port']))
				$port = 443;
			$host = 'ssl://' . $host;
		}
		$socket = fsockopen($host, $port, $errno, $errstr, 10);
		if (!$socket) {
			return "SOAP opening socket failed to $host:$port! $errstr ($errno)<br />\n";
		}

		fwrite($socket, $httpReq);
		stream_set_blocking($socket, false);
		$response = '';
		$stop = microtime(true) + $timeout;
		while (!feof($socket)) {
			$response .= fread($socket, 32000);
			if (microtime(true) > $stop)
				return "SOAP response timeout!";
		}
		fclose($socket);

		return substr($response, 0, strlen($response) - 6); // Cut 6 bytes at the end of the message
	}

	public static function processSoapMsg($soapMsg)
	{
		$pos = strpos($soapMsg, "<?xml");
		if ($pos === false)
			$pos = strpos($soapMsg, "\r\n\r\n");
		if ($pos === false)
			return "";
		$soapMsg = substr($soapMsg, $pos, strlen($soapMsg) - $pos);

		$soapXml = new SimpleXMLElement($soapMsg);
		$xmlNamespaces = $soapXml->getNamespaces(true);
		$soapXml->registerXPathNamespace("soap11", $xmlNamespaces["soap11"]);
		$soapXml->registerXPathNamespace("saml2p", $xmlNamespaces["saml2p"]);
		$bodyElement = $soapXml->xpath("//soap11:Envelope/soap11:Body/saml2p:Response");

		return $bodyElement[0]->asXML();
	}

	/**
	 * Generates (message) id.
	 *
	 * @param string $prefix
	 * @return string
	 */
	public static function generateId($prefix = 'pfx')
	{
		$uuid = md5(uniqid(rand(), true));
		$guid = $prefix . substr($uuid, 0, 8) . "-" . substr($uuid, 8, 4) . "-" . substr($uuid, 12, 4) . "-" . substr($uuid, 16, 4) . "-" . substr($uuid, 20, 12);

		return $guid;
	}

	public static function toString($s)
	{
		return "" . $s;
	}

	public static function getTime()
	{
		return date("c");
	}

	public static function parseQuery($query)
	{
		$data = array();
		$relayState = '';
		$sigAlg = '';
		foreach (explode('&', $query) as $e) {
			list($name, $value) = explode('=', $e, 2);
			$name = urldecode($name);
			$data[$name] = urldecode($value);
			switch ($name) {
				case 'SAMLRequest':
				case 'SAMLResponse':
					$sigQuery = $name . '=' . $value;
					break;
				case 'RelayState':
					$relayState = '&RelayState=' . $value;
					break;
				case 'SigAlg':
					$sigAlg = '&SigAlg=' . $value;
					break;
			}
		}
		$data['SignedQuery'] = $sigQuery . $relayState . $sigAlg;

		return $data;
	}

	public static function signXml($xml, $privKey, $cert, $idName = "ID", $appendToNodeName = null, $noRef = FALSE)
	{
		require_once(SP_SDK_ROOT . '/xmlseclibs/xmlseclibs.php');

		$doc = new DOMDocument();
		$doc->loadXML($xml);

		$root = $noRef ? $doc : $doc->documentElement;

		$objDSig = new XMLSecurityDSig();
		$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
		$options = array('id_name' => $idName, 'overwrite' => FALSE, 'force_uri' => TRUE);
		$objDSig->addReferenceList(array($root), XMLSecurityDSig::SHA256, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N), $options);
		$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
		$objKey->loadKey($privKey, TRUE);

		$objDSig->sign($objKey);
		$objDSig->add509Cert($cert);

		if ($appendToNodeName) {
			$objDSig->appendSignature($doc->getElementsByTagName($appendToNodeName)[0]);
		} else {
			$objDSig->appendSignature($doc->documentElement);
		}

		return $doc->saveXML();
	}

	public static function verifyXml($xml, $cert, $idName = "ID")
	{
		require_once(SP_SDK_ROOT . '/xmlseclibs/xmlseclibs.php');

		$doc = new DOMDocument();
		$doc->loadXML($xml);

		$objXMLSecDSig = new XMLSecurityDSig();

		$objDSig = $objXMLSecDSig->locateSignature($doc);
		if (!$objDSig)
			return FALSE;

		$objXMLSecDSig->canonicalizeSignedInfo();
		$objXMLSecDSig->idKeys = array($idName);

		if (!$objXMLSecDSig->validateReference())
			return FALSE;

		$objKey = $objXMLSecDSig->locateKey();
		$objKey->loadKey($cert);

		return $objXMLSecDSig->verify($objKey);
	}

	public static function jsonToHeader($jsonCookie)
	{
		$headerCookie = base64_decode($jsonCookie);
		$headerCookie = str_replace("{", "", $headerCookie);
		$headerCookie = str_replace("}", "", $headerCookie);
		$headerCookie = str_replace("\"", "", $headerCookie);
		$headerCookie = str_replace(":", "=", $headerCookie);

		return $headerCookie;
	}

	public static function getSoapMsg($body)
	{
		$body = str_replace("<?xml version=\"1.0\"?>", "", $body);
		$soapMsg = file_get_contents(SP_SDK_ROOT . '/templates/SoapEnvelopeTemplate.xml');
		$soapMsg = str_replace('<BODY>', $body, $soapMsg);

		return $soapMsg;
	}

	public static function startsWith($haystack, $needle)
	{
		return !strncmp($haystack, $needle, strlen($needle));
	}

	public static function extractStatusMessage($statusMessageNodes) {
		if ($statusMessageNodes != null) {
			return $statusMessageNodes[0];
		}

		return null;
	}
}

?>