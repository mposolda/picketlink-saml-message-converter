/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.gatein.test;

import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.api.saml.v2.sig.SAML2Signature;
import org.picketlink.identity.federation.core.ErrorCodes;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PicketlinkSAMLConverter
{
   private String ENCODING = System.getProperty("file.encoding");
   //private static XMLSignatureFactory fac = getXMLSignatureFactory();
   
   public String decodePostSAMLMessage(String samlResponse)
   {
      try
      {
         // First URLDecode message
         URLDecoder decoder = new URLDecoder();
         String messURLDecoded = decoder.decode(samlResponse, ENCODING);

         // Noedecode with usage of picketlink
         InputStream is = PostBindingUtil.base64DecodeAsStream(messURLDecoded);
         SAML2Response saml2Response = new SAML2Response();
         saml2Response.getSAML2ObjectFromStream(is);
         SAMLDocumentHolder documentHolder = saml2Response.getSamlDocumentHolder();

         String converted = DocumentUtil.asString(documentHolder.getSamlDocument());

         return converted;
      }
      catch (Exception e)
      {
         e.printStackTrace();
         return "ERROR. Look at server log. Message is: " + e.getMessage();
      }      
   }

   public String decodeRedirectSAMLMessage(String samlResponse)
   {
      try
      {
         // First URLDecode message
         URLDecoder decoder = new URLDecoder();
         String messURLDecoded = decoder.decode(samlResponse, ENCODING);

         // Noedecode with usage of picketlink
         InputStream is = RedirectBindingUtil.base64DeflateDecode(messURLDecoded);
         SAML2Response saml2Response = new SAML2Response();
         saml2Response.getSAML2ObjectFromStream(is);
         SAMLDocumentHolder documentHolder = saml2Response.getSamlDocumentHolder();

         String converted = DocumentUtil.asString(documentHolder.getSamlDocument());

         return converted;
      }
      catch (Exception e)
      {
         e.printStackTrace();
         return "ERROR. Look at server log. Message is: " + e.getMessage();
      }
   }
   
   public String encodePostSAMLMessage(String samlMessage)
   {
      try
      {
         String result = PostBindingUtil.base64Encode(samlMessage);
         
         // Now encode message into URL format
         result = URLEncoder.encode(result, ENCODING);

         return result;
      }
      catch (Exception e)
      {
         e.printStackTrace();
         return "ERROR. Look at server log. Message is: " + e.getMessage();
      }      
   }

   public String encodeRedirectSAMLMessage(String samlMessage)
   {
      try
      {
         String result = RedirectBindingUtil.deflateBase64URLEncode(samlMessage.getBytes(ENCODING));

         // Now encode message into URL format
         // result = URLEncoder.encode(result, ENCODING);

         return result;
      }
      catch (Exception e)
      {
         e.printStackTrace();
         return "ERROR. Look at server log. Message is: " + e.getMessage();
      }
   }

   public String signXML(String samlXMLMessage, TrustKeyManager keyManager)
   {
      try
      {
         KeyPair keyPair = keyManager.getSigningKeyPair();

         Document docToSign = DocumentUtil.getDocument(samlXMLMessage);

         SAML2Signature samlSignature = new SAML2Signature();
         Node nextSibling = samlSignature.getNextSiblingOfIssuer(docToSign);
         samlSignature.setNextSibling(nextSibling);
         samlSignature.signSAMLDocument(docToSign, keyPair);

         return DocumentUtil.asString(docToSign);

      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   public String signXMLAssertion(String samlXMLMessage, TrustKeyManager keyManager)
   {
      try
      {
         Document doc = DocumentUtil.getDocument(samlXMLMessage);

         // Obtain assertion to sign
         Element assertion = XMLSignatureUtil2.getFirstAssertionElement(doc);

         // Obtain next sibling of issuer
         Node nextSibling = XMLSignatureUtil2.getNextSiblingOfIssuer(assertion);

         // Obtain referenceURI of assertion
         String assertionId = ((Element)assertion).getAttribute("ID");
         String referenceURI = "#" + assertionId;

         // Configure ID (it's required by Santuario library)
         ((Element) assertion).setIdAttribute("ID", true);

         KeyPair keyPair = keyManager.getSigningKeyPair();

         XMLSignatureUtil2.sign(keyPair, "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", referenceURI, assertion, nextSibling);

         return DocumentUtil.asString(doc);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   public String validateSignatureOnSamlAssertion(String samlXMLMessage, TrustKeyManager keyManager)
   {
      try
      {
         Document doc = DocumentUtil.getDocument(samlXMLMessage);

         //boolean coreValidity = XMLSignatureUtil.validate(doc, keyManager.getSigningKeyPair().getPublic());

         boolean coreValidity = new SAML2Signature().validate(doc, keyManager.getSigningKeyPair().getPublic());
         return String.valueOf(coreValidity);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }
}
