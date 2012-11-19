<%
    
    String input = (String)request.getSession().getAttribute("input");
    String output = (String)request.getSession().getAttribute("output");
    boolean keystoreImported = request.getSession().getAttribute("keystoreImported") != null;

    String keyStoreImportedHelper = keystoreImported ? "" : " disabled='true' ";
%>

<html>
<body>
<h2>Picketlink SAML converter</h2>
<form method="GET" action="convert">    
    CONVERTER INPUT: <%= input %><br><br><br>
    CONVERTER OUTPUT:<%= output %><br><br><br>
    <textarea rows="4" cols="200" name="inputToConvert"></textarea><br>

    <hr>
    <br>
    <table>
    <tr>
        <td width="50%">Keystore file: <input name="keystoreURL" /></td>
        <td width="50%">Keystore password: <input name="keystorePassword" /></td>
    </tr>
    <tr>
        <td width="50%">Key Alias: <input name="keyAlias" /></td>
        <td width="50%">Private key password: <input name="keyPassword" /></td>
    </tr>
    <tr>
        <td width="50%"><input type="submit" name="submit1" value="import signing key" />
        <td width="50%">Keystore imported: <%= keystoreImported %>

    </tr></table>
    <br>
    <hr>
    <input type="submit" name="submit1" value="decode redirect SAML Message" /><br>
    <input type="submit" name="submit1" value="decode post SAML Message" /><br>
    <input type="submit" name="submit1" value="encode redirect SAML Message" /><br>
    <input type="submit" name="submit1" value="encode post SAML Message" /><br>
    <input type="submit" name="submit1" value="format previous decoding output" /><br>
    <input type="submit" name="submit1" value="sign XML with new signature (require keystore)"  <%= keyStoreImportedHelper %> /><br>
    <input type="submit" name="submit1" value="sign XML assertion with new signature (require keystore)"  <%= keyStoreImportedHelper %> /><br>
    <input type="submit" name="submit1" value="validate XML (require keystore)"  <%= keyStoreImportedHelper %> /><br>
</form>
</body>
</html>
