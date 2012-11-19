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

import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.ProvidersUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.core.util.SystemPropertiesUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class XMLSignatureUtil2
{

   // Set some system properties and Santuario providers. Run this block before any other class initialization.
   static {
      ProvidersUtil.ensure();
      SystemPropertiesUtil.ensure();
   };

   private static String canonicalizationMethodType = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;

   private static XMLSignatureFactory fac = getXMLSignatureFactory();

   /**
    * By default, we include the keyinfo in the signature
    */
   private static boolean includeKeyInfoInSignature = true;

   private static XMLSignatureFactory getXMLSignatureFactory() {
      XMLSignatureFactory xsf = null;

      try {
         xsf = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
      } catch (NoSuchProviderException ex) {
         try {
            xsf = XMLSignatureFactory.getInstance("DOM");
         } catch (Exception err) {
            throw new RuntimeException("could not create instance for DOM");
         }
      }
      return xsf;
   }

   /**
    * Sign the specified element
    */
   public static void sign(KeyPair keyPair, String digestMethod, String signatureMethod, String referenceURI,
                               Element elementToSign, Node nextSibling)
         throws GeneralSecurityException, MarshalException, XMLSignatureException
   {
      PrivateKey signingKey = keyPair.getPrivate();
      PublicKey publicKey = keyPair.getPublic();

      DOMSignContext dsc = new DOMSignContext(signingKey, elementToSign, nextSibling);
      dsc.setDefaultNamespacePrefix("dsig");

      DigestMethod digestMethodObj = fac.newDigestMethod(digestMethod, null);
      Transform transform1 = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
      Transform transform2 = fac.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null);

      List<Transform> transformList = new ArrayList<Transform>();
      transformList.add(transform1);
      transformList.add(transform2);

      Reference ref = fac.newReference(referenceURI, digestMethodObj, transformList, null, null);

      CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(canonicalizationMethodType,
            (C14NMethodParameterSpec) null);

      List<Reference> referenceList = Collections.singletonList(ref);
      SignatureMethod signatureMethodObj = fac.newSignatureMethod(signatureMethod, null);
      SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethodObj, referenceList);

      KeyInfoFactory kif = fac.getKeyInfoFactory();
      KeyValue kv = kif.newKeyValue(publicKey);
      KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

      if (!includeKeyInfoInSignature) {
         ki = null;
      }
      XMLSignature signature = fac.newXMLSignature(si, ki);

      signature.sign(dsc);
   }

   public static Element getFirstAssertionElement(Document doc)
   {
      NodeList nl = doc.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(),
            JBossSAMLConstants.ASSERTION.get());
      if (nl.getLength() == 0)
      {
         throw new RuntimeException("XML Message does not contain assertion!!!!");
      }
      if (nl.getLength() > 1)
      {
         throw new RuntimeException("XML Message contains more Assertion objects!!!");
      }
      Node assertion = nl.item(0);
      return (Element)assertion;
   }

   /**
    * Find the "Issuer" element, which is child of parent element and return next sibling of this issuer element
    */
   public static Node getNextSiblingOfIssuer(Element parent)
   {
      // Find the sibling of Issuer
      NodeList nl = parent.getElementsByTagNameNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get());
      if (nl.getLength() > 0)
      {
         Node issuer = nl.item(0);
         return issuer.getNextSibling();
      }
      return null;
   }
}
