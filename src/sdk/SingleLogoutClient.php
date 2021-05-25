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

require_once(SP_SDK_ROOT . "/utils/SamlSdkUtils.php");

/**
 * PHP SDK Single Logout Client
 */
class SingleLogoutClient
{
	private $samlConfig;

	public function __construct($samlConfig) {
		$this->samlConfig = $samlConfig;
	}

	public function generateRequest($nameId, $sessionIndex, $spLanguage = "en")
	{
		require_once(SP_SDK_ROOT . "/SamlRequest.php");
		$id = SamlSdkUtils::generateId();

		$request = file_get_contents(SP_SDK_ROOT . '/templates/LogoutRequestTemplate.xml');
		$request = str_replace('<DESTINATION>', $this->samlConfig->getSlsRedirectUrl(), $request);
		$request = str_replace('<ID>', $id, $request);
		$request = str_replace('<ISSUE_INSTANT>', SamlSdkUtils::getTime(), $request);
		$request = str_replace('<ISSUER>', $this->samlConfig->getSpEntityId(), $request);
		$request = str_replace('<NAME_ID>', $nameId, $request);
		$request = str_replace('<SESSION_INDEX>', $sessionIndex, $request);
		$request = str_replace('<ATTRIBUTE_SPLANGUAGE>', $spLanguage, $request);

		return new SamlRequest($id, $request);
	}

	public function processResponse($response, $requestId)
	{
		require_once(SP_SDK_ROOT . "/SamlCredential.php");

		$samlResponse = new SimpleXMLElement($response);
		if ($samlResponse["InResponseTo"] == $requestId) {
			$samlResponse->registerXPathNamespace("saml2p", SHIB_PROTOCOL_NS);
			$statusElement = $samlResponse->xpath("//saml2p:LogoutResponse/saml2p:Status/saml2p:StatusCode");
			$statusMessageNodes = $samlResponse->xpath("//saml2p:LogoutResponse/saml2p:Status/saml2p:StatusMessage");
			$status = $statusElement[0]["Value"];
			$success = $status == "urn:oasis:names:tc:SAML:2.0:status:Success";
			return new SamlCredential($success, $status, SamlSdkUtils::extractStatusMessage($statusMessageNodes), null, null, null, null);
		} else {
			throw new Exception("Error while getting logout response: Wrong response ID!");
		}
	}

	public function generateResponse($idpRequest)
	{
		$samlRequest = new SimpleXMLElement($idpRequest);
		$xmlNamespaces = $samlRequest->getNamespaces(true);
		$samlRequest->registerXPathNamespace("saml2p", $xmlNamespaces["saml2p"]);
		$samlRequest->registerXPathNamespace("saml2", $xmlNamespaces["saml2"]);
		$nameIdElement = $samlRequest->xpath("//saml2p:LogoutRequest/saml2:NameID");
		$nameId = $nameIdElement[0];
		$respId = $samlRequest["ID"];

		$samlResponse = file_get_contents(SP_SDK_ROOT . "/templates/LogoutResponseTemplate.xml");
		$samlResponse = str_replace('<DESTINATION>', $this->samlConfig->getSlsRedirectUrl(), $samlResponse);
		$samlResponse = str_replace('<ID>', generateId(), $samlResponse);
		$samlResponse = str_replace('<IN_RESPONSE_TO>', $respId, $samlResponse);
		$samlResponse = str_replace('<ISSUE_INSTANT>', SamlSdkUtils::getTime(), $samlResponse);
		$samlResponse = str_replace('<ISSUER>', $this->samlConfig->getSpEntityId(), $samlResponse);
		$samlResponse = str_replace('<SATUS_CODE>', "urn:oasis:names:tc:SAML:2.0:status:Success", $samlResponse);

		return $samlResponse;
	}

}

?>