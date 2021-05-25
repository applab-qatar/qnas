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
 * SAML AttributeQuery Client
 */
class AttributeQueryClient
{
	private $samlConfig;

	public function __construct($samlConfig) {
		$this->samlConfig = $samlConfig;
	}

	public function generateRequest($nameId, $attrs)
	{
		require_once(SP_SDK_ROOT . "/SamlRequest.php");

		$id = SamlSdkUtils::generateId();

		$request = file_get_contents(SP_SDK_ROOT . '/templates/AttributeQueryTemplate.xml');
		$request = str_replace('<DESTINATION>', $this->samlConfig->getAqUrl(), $request);
		$request = str_replace('<ID>', $id, $request);
		$request = str_replace('<ISSUE_INSTANT>', SamlSdkUtils::getTime(), $request);
		$request = str_replace('<ISSUER>', $this->samlConfig->getSpEntityId(), $request);
		$request = str_replace('<NAME_ID>', $nameId, $request);
		$request = str_replace('<NAME_QUALIFIER>', $this->samlConfig->getIdpEntityId(), $request);

		$attr_element = file_get_contents(SP_SDK_ROOT . '/templates/AttributeElementTemplate.xml');
		$xml_attrs = "";
		foreach ($attrs as $attr) {
			$xml_attrs .= str_replace('<NAME>', $attr, $attr_element);
		}
		$request = str_replace('<ATTRIBUTES>', $xml_attrs, $request);

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
					$issuerNodes = $samlResp->xpath("//saml2p:Response/saml2:Issuer");
					$nameId = SamlSdkUtils::toString($subjectNodes[0]);
					$idpEntityId = SamlSdkUtils::toString($issuerNodes[0]);
					$attributes = array();
					$attr_nodes = $samlResp->xpath("//saml2p:Response/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute");
					foreach ($attr_nodes as $attr) {
						$value = $attr->children($samlNamespaces["saml2"]);
						$attributes[SamlSdkUtils::toString($attr["Name"])] = array("FriendlyName" => SamlSdkUtils::toString($attr["FriendlyName"]), "value" => SamlSdkUtils::toString($value));
					}

					return new SamlCredential($success, $status, SamlSdkUtils::extractStatusMessage($statusMessageNodes), $nameId, null, $idpEntityId, $attributes);
				} else {
					return new SamlCredential($success, $status, SamlSdkUtils::extractStatusMessage($statusMessageNodes), null, null, null, null);
				}
			} else {
				throw new Exception("Error while getting attribute query response: Wrong response ID!");
			}
		} else {
			throw new Exception("Error attribute query: Unable to validate signature on SAML message response!");
		}
	}
}

?>