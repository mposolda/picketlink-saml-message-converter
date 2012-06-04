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
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;

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

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PicketlinkSAMLConverter
{
   private String ENCODING = System.getProperty("file.encoding");
   
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

}
