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
 * SAML Credentials Representation
 */
class SamlCredential
{

	/**
	 * True if the response status is success
	 */
	private $success;

	/**
	 * The SAML response status
	 */
	private $status;

	/**
	 * Status message
	 */
	private $statusMessage;

	/**
	 * The authenticated name ID of user
	 */
	private $nameId;

	/**
	 * The authentication method used
	 */
	private $authnMethod;

	/**
	 * The IDP entity ID
	 */
	private $idpEntityId;

	/**
	 * The user attributes
	 */
	private $attributes;


	public function __construct($success, $status, $statusMessage, $nameId, $authnMethod, $idpEntityId, $attributes)
	{
		$this->success = $success;
		$this->status = $status;
		$this->statusMessage = $statusMessage;
		$this->nameId = $nameId;
		$this->authnMethod = $authnMethod;
		$this->idpEntityId = $idpEntityId;
		$this->attributes = $attributes;
	}

	public function isSuccess()
	{
		return $this->success;
	}

	public function getStatus()
	{
		return $this->status;
	}

	public function getNameId()
	{
		return $this->nameId;
	}

	public function getAuthMethod()
	{
		return $this->authnMethod;
	}

	public function getIdpEntityId()
	{
		return $this->idpEntityId;
	}

	public function getAttributes()
	{
		return $this->attributes;
	}

	public function getAttributeValue($attributeName) {
		if ($this->attributes != null && $this->attributes[$attributeName] != null) {
			return $this->attributes[$attributeName]["value"];
		}

		return null;
	}

	/**
	 * @return string message or null
	 */
	public function getStatusMessage()
	{
		return $this->statusMessage;
	}
}

?>