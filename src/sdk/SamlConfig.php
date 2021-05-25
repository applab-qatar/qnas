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
 * SAML Configuration
 */
class SamlConfig
{

	/**
	 * URL of the Assertion Consumer Service
	 */
	private $acsUrl;

	/**
	 * SP metadata file
	 */
	private $spMetadataFile;

	/**
	 * IDP metadata file
	 */
	private $idpMetadataFile;

	/**
	 * SP private key file to sign SAML messages
	 */
	private $spPrivateKeyFile;

	/**
	 * SP public certificate file to include into the SAML messages
	 */
	private $spCertFile;

	private $xmlSp;
	private $xmlIdp;

	private $slsRedirectUrl = null;


	public function __construct($spMetadataFile, $idpMetadataFile, $spPrivateKeyFile, $spCertFile)
	{
		$this->acsUrl = null;
		$this->spMetadataFile = $spMetadataFile;
		$this->idpMetadataFile = $idpMetadataFile;
		$this->spPrivateKeyFile = $spPrivateKeyFile;
		$this->spCertFile = $spCertFile;
		$this->xmlSp = simplexml_load_file($spMetadataFile);
		$this->xmlIdp = simplexml_load_file($idpMetadataFile);
	}

	public function getAcsUrl()
	{
		if ($this->acsUrl == null) {
			$this->xmlSp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
			$entityDescElement = $this->xmlSp->xpath("//x:AssertionConsumerService");
			$this->acsUrl = $entityDescElement[0]["Location"];
			return $entityDescElement[0]["Location"];
		} else {
			return $this->acsUrl;
		}
	}

	public function getSpPrivateKeyFile()
	{
		return $this->spPrivateKeyFile;
	}

	public function getSpCertFile()
	{
		return $this->spCertFile;
	}


	function getSpEntityId()
	{
		$this->xmlSp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
		$entityDescElement = $this->xmlSp->xpath("//x:EntityDescriptor");
		return (string)$entityDescElement[0]["entityID"];
	}

	function getIdpEntityId()
	{
		return $this->xmlIdp["entityID"];
	}

	function getIdpBaseUrl()
	{
		preg_match('/(http[s]?:\/\/.*\/idp\/).*\/saml\/slo/', $this->getSlsRedirectUrl(), $matches);
		if (!empty($matches) && count($matches) >= 2) {
			return $matches[1];
		}
		return $this->getSlsRedirectUrl();
	}

	public function getSsoPostUrl()
	{
		$this->xmlIdp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
		$ssoElements = $this->xmlIdp->xpath("//x:EntityDescriptor/x:IDPSSODescriptor/x:SingleSignOnService");
		foreach ($ssoElements as $element) {
			if ($element["Binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") {
				return $element["Location"];
			}
		}

		return "";
	}

	public function getSsoRedirectUrl()
	{
		$this->xmlIdp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
		$ssoElements = $this->xmlIdp->xpath("//x:EntityDescriptor/x:IDPSSODescriptor/x:SingleSignOnService");
		foreach ($ssoElements as $element) {
			if ($element["Binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") {
				return $element["Location"];
			}
		}

		return "";
	}

	public function getSlsRedirectUrl()
	{
		if ($this->slsRedirectUrl == null) {
			$this->xmlIdp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
			$sloElements = $this->xmlIdp->xpath("//x:EntityDescriptor/x:IDPSSODescriptor/x:SingleLogoutService");
			foreach ($sloElements as $element) {
				if ($element["Binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") {
					$this->slsRedirectUrl = (string)$element["Location"];
					return (string)$element["Location"];
				}
			}
			return "";
		} else {
			return $this->slsRedirectUrl;
		}
	}

	public function getAqUrl()
	{
		$this->xmlIdp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
		$aqElements = $this->xmlIdp->xpath("//x:EntityDescriptor/x:AttributeAuthorityDescriptor/x:AttributeService");
		foreach ($aqElements as $element) {
			if ($element["Binding"] == "urn:oasis:names:tc:SAML:2.0:bindings:SOAP") {
				return $element["Location"];
			}
		}

		return "";
	}

	function getSpCert()
	{
		return file_get_contents($this->spCertFile, true);
	}

	function getIdpCert()
	{
		$xmlNamespaces = $this->xmlIdp->getNamespaces(true);
		$this->xmlIdp->registerXPathNamespace("x", "urn:oasis:names:tc:SAML:2.0:metadata");
		$this->xmlIdp->registerXPathNamespace("ds", $xmlNamespaces["ds"]);
		$certElement = $this->xmlIdp->xpath("//x:EntityDescriptor/x:IDPSSODescriptor/x:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate");
		$cert = str_replace(" ", "", $certElement[0]);
		$cert = str_replace("\n", "", $cert);
		$cert = "-----BEGIN CERTIFICATE-----\n" . $cert . "\n-----END CERTIFICATE-----";

		return $cert;
	}

}

?>
