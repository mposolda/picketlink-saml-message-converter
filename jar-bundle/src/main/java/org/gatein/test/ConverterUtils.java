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

import org.picketlink.identity.federation.core.config.AuthPropertyType;
import org.picketlink.identity.federation.core.impl.KeyStoreKeyManager;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ConverterUtils
{

   private ConverterUtils() {}

   public static TrustKeyManager getTrustKeyManager(String keystoreFile, String keystorePassword, String keyAlias, String keyPassword)
   {

      try
      {
         TrustKeyManager keyManager = new KeyStoreKeyManager();

         List<AuthPropertyType> authProperties = new ArrayList<AuthPropertyType>();
         authProperties.add(getAuthProperty(KeyStoreKeyManager.KEYSTORE_URL, keystoreFile));
         authProperties.add(getAuthProperty(KeyStoreKeyManager.KEYSTORE_PASS, keystorePassword));
         authProperties.add(getAuthProperty(KeyStoreKeyManager.SIGNING_KEY_ALIAS, keyAlias));
         authProperties.add(getAuthProperty(KeyStoreKeyManager.SIGNING_KEY_PASS, keyPassword));
         keyManager.setAuthProperties(authProperties);

         return keyManager;
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   private static AuthPropertyType getAuthProperty(String key, String value)
   {
      AuthPropertyType type = new AuthPropertyType();
      type.setKey(key);
      type.setValue(value);
      return type;
   }
}
