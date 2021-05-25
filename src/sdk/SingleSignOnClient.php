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
 * PHP SDK Single Sign On Client
 */
class SingleSignOnClient
{
	private $samlConfig;

	public function __construct($samlConfig)
	{
		$this->samlConfig = $samlConfig;
	}

	public function generateRequest($language = "en", $authnMethods = array(), $forceAuthn = false)
	{
		require_once(SP_SDK_ROOT . "/SamlRequest.php");

		$id = SamlSdkUtils::generateId();

		$request = file_get_contents(SP_SDK_ROOT . '/templates/AuthnRequestTemplate.xml');
		$request = str_replace('<ACS_URL>', $this->samlConfig->getAcsUrl(), $request);
		$request = str_replace('<DESTINATION>', $this->samlConfig->getSsoPostUrl(), $request);
		$request = str_replace('<ID>', $id, $request);
		$request = str_replace('<ISSUE_INSTANT>', SamlSdkUtils::getTime(), $request);
		$request = str_replace('<ISSUER>', $this->samlConfig->getSpEntityId(), $request);
		$request = str_replace('<ATTRIBUTE_SPLANGUAGE>', $language, $request);
		$request = str_replace('<FORCE_AUTHN>', $forceAuthn, $request);
		$request = str_replace('<REQUESTED_AUTHN_METHODS>', $this->createRequestedAuthnMethods($authnMethods), $request);

		$request = SamlSdkUtils::signXml($request, $this->samlConfig->getSpPrivateKeyFile(), $this->samlConfig->getSpCert());

		return new SamlRequest($id, $request);
	}

	public function processResponse($response, $requestId)
	{
		require_once(SP_SDK_ROOT . "/SamlCredential.php");

		if (SamlSdkUtils::verifyXml($response, $this->samlConfig->getIdpCert())) {
			$samlResp = new SimpleXMLElement($response);
			if (isset($requestId) && $samlResp["InResponseTo"] == $requestId) {
				$samlNamespaces = $samlResp->getNamespaces(true);
				$statusNodes = $samlResp->xpath("//saml2p:Response/saml2p:Status/saml2p:StatusCode");
				$statusMessageNodes = $samlResp->xpath("//saml2p:Response/saml2p:Status/saml2p:StatusMessage");
				$status = $statusNodes[0]["Value"];
				$success = $status == "urn:oasis:names:tc:SAML:2.0:status:Success";

				if ($success) {
					$samlResp->registerXPathNamespace("saml2", SHIB_ASSERT_NS);
					$samlResp->registerXPathNamespace("saml2p", SHIB_PROTOCOL_NS);
					$subjectNodes = $samlResp->xpath("//saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID");
					$authnConNodes = $samlResp->xpath("//saml2p:Response/saml2:Assertion/saml2:AuthnStatement/saml2:AuthnContext/saml2:AuthnContextClassRef");
					$issuerNodes = $samlResp->xpath("//saml2p:Response/saml2:Issuer");
					$nameId = SamlSdkUtils::toString($subjectNodes[0]);
					$authnMethod = SamlSdkUtils::toString($authnConNodes[0]);
					$idpEntityId = SamlSdkUtils::toString($issuerNodes[0]);
					$attributes = array();
					$attr_nodes = $samlResp->xpath("//saml2p:Response/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute");
					foreach ($attr_nodes as $attr) {
						$value = $attr->children($samlNamespaces["saml2"]);
						$attributes[SamlSdkUtils::toString($attr["Name"])] = array("FriendlyName" => SamlSdkUtils::toString($attr["FriendlyName"]), "value" => SamlSdkUtils::toString($value));
					}

					return new SamlCredential($success, $status, SamlSdkUtils::extractStatusMessage($statusMessageNodes), $nameId, $authnMethod, $idpEntityId, $attributes);
				} else {
					return new SamlCredential($success, $status, SamlSdkUtils::extractStatusMessage($statusMessageNodes), null, null, null, null);
				}
			} else {
				throw new Exception("Error while getting login response: Wrong response ID!");
			}
		} else {
			throw new Exception("Error login: Unable to validate signature on SAML message response!");
		}
	}

	/**
	 * Creates requested methods XML elements.
	 *
	 * @param $authnMethods array with method URIs
	 * @return string XML elements
	 */
	private function createRequestedAuthnMethods($authnMethods) {
		$requestedAuthnMethods = '';
		if ($authnMethods != null) {
			foreach ($authnMethods as $authnMethodUri) {
				$requestedAuthnMethods .= "<saml2:AuthnContextClassRef xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">$authnMethodUri</saml2:AuthnContextClassRef>";
			}
		}

		return $requestedAuthnMethods;
	}
}


?>