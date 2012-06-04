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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ConverterServlet extends HttpServlet
{
   private PicketlinkSAMLConverter converter = new PicketlinkSAMLConverter(); 
   
   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      HttpSession sess = request.getSession();
      String inputToConvert = request.getParameter("inputToConvert");
      String submit1 = request.getParameter("submit1");

      if ("format previous decoding output".equals(submit1))
      {
         response.setContentType("text/xml");
         response.getWriter().println(sess.getAttribute("outputAsXML"));
         response.getWriter().flush();
         response.getWriter().close();
         return;
      }

      if (inputToConvert != null)
      {
         String output = convert(inputToConvert, submit1);

         System.out.println("CONVERTED OUTPUT: " + output);
         sess.setAttribute("outputAsXML", output);

         // convert output, so it can be displayed in HTML page
         output = htmlOutputConvert(output);

         sess.setAttribute("input", inputToConvert);
         sess.setAttribute("output", output);
      }
      
      request.getRequestDispatcher("/index.jsp").forward(request, response);
      
   }
   
   private String convert(String input, String submit)
   {
      if ("decode redirect SAML Message".equals(submit))
      {
         return converter.decodeRedirectSAMLMessage(input);
      }
      else if ("decode post SAML Message".equals(submit))
      {
         return converter.decodePostSAMLMessage(input);
      }
      else if ("encode redirect SAML Message".equals(submit))
      {
         return converter.encodeRedirectSAMLMessage(input);
      }
      else if ("encode post SAML Message".equals(submit))
      {
         return converter.encodePostSAMLMessage(input);
      }

      // TODO
      return "ERROR - not known submit";
   }

   private String htmlOutputConvert(String input)
   {
      return input.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
   }
}
